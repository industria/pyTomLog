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

class BotStatistics(object):
    def __init__(self):
        self.__agents = {}
        self.__bot_agents = {}
        self.__agents_seen = 0

        self.__bot_expressions = []
        self.__bot_expressions.append(re.compile('(ads|google|bing|msn|yandex|baidu|ro|career|seznam|)bot', re.IGNORECASE))
        self.__bot_expressions.append(re.compile('(baidu|jike|symantec)spider', re.IGNORECASE))
        self.__bot_expressions.append(re.compile('scanner', re.IGNORECASE))
        self.__bot_expressions.append(re.compile('(web)crawler', re.IGNORECASE))
        pass

    def _isBot(self, useragent):
        """
        Classify the useragent as bot or not a bot.
        """
        for expression in self.__bot_expressions:
            match = expression.search(useragent)
            if match:
                return True
        return False

    def _addAgent(self, agent):
        if agent in self.__agents:
            self.__agents[agent] = self.__agents[agent] + 1
        else:
            self.__agents[agent] = 1

    def _addBotAgent(self, agent):
        if agent in self.__bot_agents:
            self.__bot_agents[agent] = self.__bot_agents[agent] + 1
        else:
            self.__bot_agents[agent] = 1

    
    def consume(self, log_entry):
        agent = log_entry.useragent
        self.__agents_seen = self.__agents_seen + 1
        if self._isBot(agent):
            self._addBotAgent(agent)
        else:
            self._addAgent(agent)
            

    def print_statistics(self):
        ordered_most_seen = sorted(self.__agents.items(), key=operator.itemgetter(1))
        for t in ordered_most_seen:
            print(t)
        print("Unique user agent strings {:d} out of {:d} entries".format(len(self.__agents), self.__agents_seen))
        ordered_bots = sorted(self.__bot_agents.items(), key=operator.itemgetter(1))
        for t in ordered_bots:
            print(t)
        print("Unique bot user agent strings {:d} out of {:d} entries".format(len(self.__bot_agents), self.__agents_seen))
        

            
    
class UserAgents(object):
    """
    User agents object for summeriazing the user agent data.
    """
    def __init__(self, files, bot):
        """
        Construct the UserAgents object with a list of file to process.
        """
        self.__files = files;
        self.__bot_feature = bot
        pass


    def process(self):
        """
        Process the list of files.
        """
        parser = ApacheCombinedLineParser()
        bots = BotStatistics()
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
                else:
                    print(line)
            print('File {:s} has lines {:d} where {:d} matches'.format(logfile.name, lines, matchedlines))

        if(self.__bot_feature):
            bots.print_statistics()
    

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='User agents from Tomcat combined access log.')
    parser.add_argument('--bot', dest='bot', action='store_true')
    parser.set_defaults(bot=False)
    parser.add_argument('files', metavar='FILE', type=argparse.FileType(mode='r', encoding='latin-1'), nargs='+', help='File to parse')
    args = parser.parse_args()

    userAgents = UserAgents(args.files, args.bot)
    userAgents.process()

