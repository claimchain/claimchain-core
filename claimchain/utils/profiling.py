import time
import statistics as stats

from collections import defaultdict

from defaultcontext import with_default_context


@with_default_context
class Profiler(object):
    def __init__(self, prefix=''):
        self.data = defaultdict(list)
        self._prefix = prefix

    def compute_stats(self):
        result = {}
        for func_name, data_points in self.data.items():
            result[self._prefix + func_name] = {
                'avg': stats.mean(data_points),
                'min': min(data_points),
                'max': max(data_points),
                'num': len(data_points)
            }
            if len(data_points) >= 2:
                result[func_name]['std'] = stats.stdev(data_points)

        return result

    def __repr__(self):
        return 'Profiler(%s)' % repr(self.compute_stats)


def profiled(func):
    def wrapped(*args, **kwargs):
        profiler = Profiler.get_default()
        if profiler is None:
            return func(*args, **kwargs)

        t0 = time.time()
        result = func(*args, **kwargs)
        t1 = time.time()
        profiler.data[func.__name__].append(t1 - t0)
        return result

    return wrapped

