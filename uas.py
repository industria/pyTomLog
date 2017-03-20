#!/usr/bin/env python

import argparse
import operator
import re


class ApacheCombined(object):
    def __init__(self, remote_host, remote_user, date_time, request_line, status_code, bytes_sent, referrer, useragent):
        self.remote_host = remote_host
        self.remote_user = remote_user
        self.date_time = date_time
        self.request_line = request_line
        self.status_code = status_code
        self.bytes_sent = bytes_sent
        self.referrer = referrer
        self.useragent = useragent
        pass
    
class ApacheCombinedLineParser(object):
    def __init__(self):
        """
        Combined format is:
        
        %h %l %u %t "%r" %s %b "%{Referer}i" "%{User-Agent}i"
        
        where the items are:
        
        %h - Remote host name (or IP address if enableLookups for the connector is false)
        %l - Remote logical username from identd (always returns '-')
        %u - Remote user that was authenticated
        %t - Date and time, in Common Log Format format
        %r - First line of the request
        %s - HTTP status code of the response
        %b - Bytes sent, excluding HTTP headers, or '-' if no bytes were sent
        """
        self.__lineexpression = re.compile('^(\d+\.\d+\.\d+\.\d+)\s-\s(\S+)\s\[([^\]]+)\]\s"(.+)HTTP/1.[01]"\s(\d+)\s(\d+|-)\s"([^"]*)"\s"(.*)"$')

    def parse(self, line):
        """
        Parse a log line returning a ApacheCombined object or None if the line is not valid
        """
        match = self.__lineexpression.match(line)
        if match:
            remote_host = match.group(1)
            remote_user = match.group(2)
            date_time = match.group(3)
            request_line = match.group(4)
            status_code = match.group(5)
            bytes_sent = match.group(6)
            referrer = match.group(7)
            useragent = match.group(8)
            return ApacheCombined(remote_host, remote_user, date_time, request_line, status_code, bytes_sent, referrer, useragent)
        else:
            return None

class FacebookStatistics(object):
    def __init__(self):
        self.__facebook_identifiers = {}
        self.__agents_seen = 0
        self.__facebook_agents_seen = 0
        self.__facebook_agent_expression = re.compile('\[FB.+\]', re.IGNORECASE)
        # [FB_IAB/FB4A;FBAV/47.0.0.25.125;]
        #[FBAN/FBIOS;FBAV/20.0.0.14.10;FBBV/5674926;FBDV/iPad2,7;FBMD/iPad;FBSN/iPhone OS;FBSV/9.3.5;FBSS/1; FBCR/TelenorDK;FBID/tablet;FBLC/da_DK;FBOP/1]
        #[FBAN/MessengerForiOS;FBAV/102.0.0.25.70;FBBV/48148560;FBRV/0;FBDV/iPhone5,2;FBMD/iPhone;FBSN/iOS;FBSV/10.2;FBSS/2;FBCR/TELIA;FBID/phone;FBLC/sv_SE;FBOP/5]
        pass

    def _isInAppAgent(self, useragent):
        match = self.__facebook_agent_expression.search(useragent)
        if match:
            facebook_identifier = match[0]
            if facebook_identifier in self.__facebook_identifiers:
                self.__facebook_identifiers[facebook_identifier] = self.__facebook_identifiers[facebook_identifier] + 1
            else:
                self.__facebook_identifiers[facebook_identifier] = 1
            return True
        else:
            return False
        
    
    def consume(self, log_entry):
        agent = log_entry.useragent
        self.__agents_seen = self.__agents_seen + 1
        if self._isInAppAgent(agent):
            self.__facebook_agents_seen = self.__facebook_agents_seen + 1
        
    def print_statistics(self):
        for t in self.__facebook_identifiers.items():
            print("{:d} {:s}".format(t[1], t[0]))

        print("Total Facebook in-App agents {:d} of {:d} agents in total".format(self.__facebook_agents_seen, self.__agents_seen))
        facebook_percentage = (float(self.__facebook_agents_seen) / float(self.__agents_seen)) * 100
        print("Facebook App traffic accounts for {:f}% of the total volumn".format(facebook_percentage))

    
class BotStatistics(object):
    def __init__(self):
        self.__bot_agents = {}
        self.__agents_seen = 0
        self.__bot_agents_seen = 0
        

        self.__bot_expressions = []
        self.__bot_expressions.append(re.compile('(ads|google|bing|msn|yandex|baidu|ro|career|seznam|)bot', re.IGNORECASE))
        self.__bot_expressions.append(re.compile('(baidu|jike|symantec)spider', re.IGNORECASE))
        self.__bot_expressions.append(re.compile('scanner', re.IGNORECASE))
        self.__bot_expressions.append(re.compile('(web)crawler', re.IGNORECASE))
        self.__bot_expression_google_mobile = re.compile('\(compatible; Googlebot-Mobile/2.1; \+http://www.google.com/bot.html\)')
        self.__bot_expression_android_iphone = re.compile('(Android|iPhone)')
        self.__bot_expression_googlebot = re.compile('\(compatible.?; Googlebot/2.1.?; \+http://www.google.com/bot.html')
        self.__bot_expression_iphone_winphone = re.compile('(iPhone|Windows Phone)')
        self.__bot_expression_bing = re.compile('\(compatible; bingbot/2.0; \+http://www.bing.com/bingbot.htm')
        pass

    def _isMobileBot(self, useragent):
        """
        Classify the useragent as a mobile bot.
        """
        matchGoogleMobile = self.__bot_expression_google_mobile.search(useragent)
        if matchGoogleMobile:
            return True
        else:
            match_phone = self.__bot_expression_android_iphone.search(useragent)
            match_googlebot = self.__bot_expression_googlebot.search(useragent)
            if match_phone and match_googlebot:
                return True
            else:
                match_phone = self.__bot_expression_iphone_winphone.search(useragent)
                match_bingbot = self.__bot_expression_bing.search(useragent)
                return match_phone and match_bingbot

    def _isBot(self, useragent):
        """
        Classify the useragent as bot or not a bot.
        """
        for expression in self.__bot_expressions:
            match = expression.search(useragent)
            if match:
                return True
        return False

    def _addBotAgent(self, agent):
        if agent in self.__bot_agents:
            self.__bot_agents[agent] = self.__bot_agents[agent] + 1
        else:
            self.__bot_agents[agent] = 1

    
    def consume(self, log_entry):
        agent = log_entry.useragent
        self.__agents_seen = self.__agents_seen + 1
        if self._isMobileBot(agent) or self._isBot(agent):
            self.__bot_agents_seen = self.__bot_agents_seen + 1
            self._addBotAgent(agent)
            

    def print_statistics(self):
        ordered_bots = sorted(self.__bot_agents.items(), key=operator.itemgetter(1), reverse=True)
        for t in ordered_bots:
            print("{:d} {:s}".format(t[1], t[0]))
        print("Unique bots {:d} out of {:d} bot entries in {:d} agents in total".format(len(self.__bot_agents), self.__bot_agents_seen, self.__agents_seen))
        bot_percentage = (float(self.__bot_agents_seen) / float(self.__agents_seen)) * 100
        print("Bot traffic accounts for {:f}% of the total volumn".format(bot_percentage))
        

            
    
class UserAgents(object):
    """
    User agents object for summeriazing the user agent data.
    """
    def __init__(self, files, bot, facebook):
        """
        Construct the UserAgents object with a list of file to process.
        """
        self.__files = files;
        self.__bot_feature = bot
        self.__facebook_feature = facebook
        pass


    def process(self):
        """
        Process the list of files.
        """
        parser = ApacheCombinedLineParser()
        bots = BotStatistics()
        facebook = FacebookStatistics()
        for logfile in self.__files:
            lines = 0
            matchedlines = 0
            for line in logfile:
                lines = lines + 1
                match = parser.parse(line)
                if(match):
                    matchedlines = matchedlines + 1
                    if(self.__bot_feature):
                        bots.consume(match)
                    if(self.__facebook_feature):
                        facebook.consume(match)
                else:
                    print(line)
            print('File {:s} has lines {:d} where {:d} matches'.format(logfile.name, lines, matchedlines))

        if(self.__bot_feature):
            bots.print_statistics()
        if(self.__facebook_feature):
            facebook.print_statistics()
    

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='User agents from Tomcat combined access log.')
    parser.add_argument('--bot', dest='bot', action='store_true')
    parser.set_defaults(bot=False)
    parser.add_argument('--facebook', dest='facebook', action='store_true')
    parser.set_defaults(facebook=False)
    parser.add_argument('files', metavar='FILE', type=argparse.FileType(mode='r', encoding='latin-1'), nargs='+', help='File to parse')
    args = parser.parse_args()

    userAgents = UserAgents(args.files, args.bot, args.facebook)
    userAgents.process()

