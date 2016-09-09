# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging
import multiprocessing
import Queue
import threading

LOG = logging.getLogger(__name__)
MAX_THREADS = multiprocessing.cpu_count() + 1


class TimeoutError(Exception):
    """Exception raised when an api thread times-out"""
    pass


class ApiThread(threading.Thread):
    def __init__(self, target=None, name=None,
                 args=(), kwargs=None, verbose=None):
        if kwargs is None:
            kwargs = {}
        self.target = target
        self.args = args
        self.kwargs = kwargs
        self.result = None
        self.error = None
        super(ApiThread, self).__init__(name=name, verbose=verbose)

    def run(self):
        try:
            self.result = self.target(*self.args, **self.kwargs)
        except Exception as e:
            self.error = e
            LOG.error('%s: %s' % (type(e), str(e)))
        finally:
            del self.target, self.args, self.kwargs


class ApiWorker(threading.Thread):
    def __init__(self, pool):
        self.pool = pool
        self.task = None
        super(ApiWorker, self).__init__()

    def run(self):
        while not self.pool.stop_workers.is_set():
            try:
                self.task = self.pool.queue.get(timeout=1)
            except Queue.Empty:
                # Nothing else to work with, so we stop.
                break
            else:
                try:
                    self.task.run()
                except Exception:
                    raise
                finally:
                    # Avoid a refcycle
                    self.pool.queue.task_done()
                    self.task = None
        # Avoid a refcycle
        self.pool = None

    def __repr__(self):
        repr = super(ApiWorker, self).__repr__()
        if self.task:
            return "%s running %r" % (repr, self.task)
        return repr


class ApiPool(object):
    def __init__(self, target_dict=None):
        """Creates a pool of api calls to launch in parallel threads.

        *target_dict* is a dict of the form::

            {
                'name': (callback, args, kwargs),
                ...
            }

        Where `name` is the name of the api call, callback is the api function
        to run, `args` a list of arguments to pass to the api call and `kwargs`
        a dict of keyword arguments to pass to the function call.

        """

        self.queue = None
        self.api_threads = []
        self.stop_workers = None
        if target_dict is not None:
            for name, value in target_dict.iteritems():
                callback = value[0]
                try:
                    args = value[1]
                except IndexError:
                    args = ()
                try:
                    kwargs = value[2]
                except IndexError:
                    kwargs = {}
                self.append(name, callback, *args, **kwargs)

    def append_thread(self, api_thread):
        self.api_threads.append(api_thread)

    def append(self, name, callback, *args, **kwargs):
        self.append_thread(ApiThread(
            name=name, target=callback, args=args, kwargs=kwargs
        ))

    def start(self):
        """Run in parallel

        If we have <= MAX_THREADS we launch them all, otherwise we spawn
        MAX_THREADS workers and queue the tasks to avoid having too many
        threads.
        """
        if len(self.api_threads) <= MAX_THREADS:
            # Launch all threads
            self.start_all()
        else:
            # Limit to MAX_THREADS amount of workers.
            self.stop_workers = threading.Event()
            self.queue = Queue.Queue()
            self.api_workers = [ApiWorker(self) for _ in xrange(MAX_THREADS)]
            for api_thread in self.api_threads:
                self.queue.put(api_thread)
            for worker in self.api_workers:
                worker.start()

    def start_all(self):
        """Run all in parallel"""
        for api_thread in self.api_threads:
            api_thread.start()

    def run(self):
        """Run in series"""
        for api_thread in self.api_threads:
            api_thread.run()

    def join(self, timeout=None):
        """Wait for all threads to finish"""
        if self.queue is not None:
            self.queue.join()
            self.stop_workers.set()
            for worker in self.api_workers:
                if worker.is_alive():
                    worker.join(timeout=timeout)
                    if worker.is_alive():
                        raise TimeoutError(
                            'Worker %s failed to respond within %s seconds' % (
                                worker, timeout
                            )
                        )
            self.queue = None
        else:
            for thread in self.api_threads:
                if thread.is_alive():
                    thread.join(timeout=timeout)
                    if thread.is_alive():
                        raise TimeoutError(
                            'Thread %s failed to respond within %s seconds' % (
                                thread, timeout)
                        )

    def get_results(self, timeout=None):
        self.join(timeout)
        return {
            api_thread.name: api_thread.result
            for api_thread in self.api_threads
        }

    def get_errors(self, timeout=None):
        self.join(timeout)
        return {
            api_thread.name: api_thread.error
            for api_thread in self.api_threads
        }

    def has_errors(self):
        for api_thread in self.api_threads:
                if api_thread.error:
                    return True
        return False

    def raise_caught_errors(self):
        if self.has_errors():
            for name, err in self.get_errors().iteritems():
                if err:
                    # The error was caught in another thread. We need to
                    # raise it for the parent thread to catch it.
                    raise err
