# -*- coding:utf-8 -*-

from errno import errorcode
import sys, os, ctypes, select, re, syslog, threading, time
from struct import Struct

IN_MODIFY = 2
IN_DELETE_SELF = 1024
IN_MOVE_SELF = 2048
IN_STOPMASK = IN_DELETE_SELF | IN_MOVE_SELF


class INotify(object):
    def __init__(self, event_token, time_out = 0.05, \
            epoll_mask = select.EPOLLIN | select.EPOLLOUT | select.EPOLLPRI | select.EPOLLERR):
        self.LIBC = ctypes.CDLL("libc.so.6")
        self.inotify_fd = self.LIBC.inotify_init()
        if self.inotify_fd < 0:
            raise OSError("Could not init inotify : " + errorcode[-self.inotify_fd])
        self._inotify_struct = Struct("iIII")
        self._event = event_token
        self._time_out = time_out
        self.e = select.epoll()
        self.e.register(self.inotify_fd)
        
    def __enter__(self):
        return self
        
    def __exit__(self):
        self.close()
        
    def close(self):
        if self.e:
            self.e.unregister(self.inotify_fd)
            self.e.close()
        os.close(self.inotify_fd)
        
    def add_watch(self, filename_fullpath, \
            mask = IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF):
        fn = None
        if not isinstance(filename_fullpath, bytes):
            fn = filename_fullpath.encode()
        else:
            fn = filename_fullpath
        watch_id = self.LIBC.inotify_add_watch(self.inotify_fd, fn, mask)
        if watch_id < 0:
            raise OSError("Could not add watch : " + errorcode[-watch_id])
        return watch_id
            
    def next_event(self):
        while True:
            #print "x"
            if self._event.is_set():
                return None
            events = self.e.poll(self._time_out)
            if len(events) == 0:
                # Just timeout
                #print "y"
                continue
            else:
                break
        #print "ABC"
        for fd, event_type in events:
            #print "B"
            if event_type & select.EPOLLIN:
                #print "CQWER"
                raw = os.read(fd, self._inotify_struct.size)
                #print "D"
                watch_id, mask, cookie, name_size = self._inotify_struct.unpack(raw)
                #print "E"
                #print watch_id, mask, cookie, name_size
                return watch_id, mask, cookie, name_size
                
class Entry(threading.Thread):
    def __init__(self, log_re_pattern, log_location, block_size = 8192,  \
            syslog_ident = "CUSTOM", syslog_facility = syslog.LOG_LOCAL0 , syslog_logoption = syslog.LOG_CONS):
        super(Entry, self).__init__()
        self._event = threading.Event()
        self._location = log_location.encode()
        self._blocksize = block_size
        self._re = re.compile(log_re_pattern, re.DOTALL)
        #self._match_token = None

        self.syslog_ident = syslog_ident
        self.syslog_facility = syslog_facility
        self.syslog_logoption = syslog_logoption
        self.newfile_flag = False
        self.buffer = ""
        
        self._watch_id = None
        self._inotify = INotify(self._event)
        self._watch_id = self._inotify.add_watch(self._location)
        
        syslog.openlog(self.syslog_ident, self.syslog_logoption, self.syslog_facility)
        
    def extract(self):
        raise NotImplementedError

    def filter(self, matched_token):
        raise NotImplementedError

    def reform(self, matched_token):
        raise NotImplementedError
        
    def follow(self):
        file_pos = 0
        with open(self._location, "rb") as fileobj:
            if self.newfile_flag:
                self.newfile_flag = False
            else:
                fileobj.seek(0,2)
                file_pos = fileobj.tell()
            while True:
                while True:
                    #print "ASDF"
                    data = fileobj.read(self._blocksize)
                    if not data:
                        break
                    #print "ZAXSCD"
                    file_pos += len(data)
                    yield data
                pack = self._inotify.next_event()
                if pack:
                    watch_id, mask, cookie, name_size = pack
                else:
                    break
                #print "1Q2W"
                if mask & IN_STOPMASK:
                    self.newfile_flag = True
                    #return None
                #print "1A2S"
                    
    def stop(self):
        self._event.set()
        syslog.closelog()
                    
    def run(self):
        while not self._event.is_set():
            if not os.path.isfile(self._location):
                import time
                time.sleep(3000)
                continue
                
            for data in self.follow():
                if not data:
                    break
                #print "POI-1"
                #print data
                #print "POI-2"
                self.buffer += data
                for matched_token in self.extract():
                    if self.filter(matched_token):
                        print self.reform(matched_token)
                        #syslog.syslog(self.reform(matched_token))
        
class uWSGI(Entry):
    def __init__(self, log_re_pattern, log_location, block_size = 8192,  \
            syslog_ident = "uWSGI", syslog_facility = syslog.LOG_LOCAL0 , syslog_logoption = syslog.LOG_CONS):
        super(uWSGI, self).__init__(log_re_pattern, log_location, block_size, \
            syslog_ident, syslog_facility, syslog_logoption)
            
    def extract(self):
        matched_token_list = []
        while True:
            matched_token = self._re.match(self.buffer)
            if not matched_token:
                break
            matched_token_list.append(matched_token)
            border = matched_token.span(0)[1]
            self.buffer = self.buffer[border:]
        
        #print "MATCHED COUNT %d, BUFFER LENGTH %d" % (matched_token_list.__len__(), self.buffer.__len__())
        return matched_token_list
        
    def filter(self, matched_token):
        if matched_token.groupdict()["response_code"] == "200":
            return True
        else:
            return True
            
    def reform(self, matched_token):
        d = matched_token.groupdict()
        return "[%s] (%s %s) %sms, %sbytes, msg : \n %s" % (d["response_code"], d["method"], d["address"], d["msecs"], d["bytes"], d["message"])
        
        
if __name__ == "__main__":
    try:
        u = uWSGI(r"(?P<main>(?P<message>.*?)\[pid: (?P<pid>\d+?)\|app: (?P<app>\d+?)\|req: (?P<req>[\d/]+?)\] (?P<remote_ip>\d+\.\d+\.\d+\.\d+) \(\) \{(?P<vars>\d+?) vars in (?P<bytes>\d+?) bytes\} \[(?P<datetime>\w+? \w+? \d+? \d+?:\d+?:\d+? \d+?)\] (?P<method>\w+?) (?P<address>[\w/]+?) => generated \d+ bytes in (?P<msecs>\d+?) msecs \(HTTP/[\d\.]+? (?P<response_code>\d+?)\) \d+ headers in \d+ bytes \((?P<switches>\d+) \w+ on core (?P<core>\d+)\)\n)",
                "/var/log/uwsgi/app/sadari.log")
        u.start()
        while True:
            time.sleep(500)
    except KeyboardInterrupt:
        #print "KeyboardInterrupt"
        u.stop()