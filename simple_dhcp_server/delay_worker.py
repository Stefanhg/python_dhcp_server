import queue
import threading
import time


class DelayWorker(object):

    def __init__(self):
        self.closed = False
        self.queue = queue.Queue()
        self.thread = threading.Thread(target=self._delay_response_thread)
        self.thread.start()

    def _delay_response_thread(self):
        while not self.closed:
            if self.closed:
                break
            try:
                p = self.queue.get(timeout=1)
                t, func, args, kw = p
                now = time.time()
                if now < t:
                    time.sleep(0.01)
                    self.queue.put(p)
                else:
                    func(*args, **kw)
            except queue.Empty:
                continue

    def do_after(self, seconds, func, args=(), kw={}):
        self.queue.put((time.time() + seconds, func, args, kw))

    def close(self):
        self.closed = True
