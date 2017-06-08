from claimchain.utils.profiling import Profiler, profiled

@profiled
def decorated(x):
    return x ** 2


def test_profiler_decorator():
    with Profiler().as_default() as profiler:
        assert decorated(2) == 4
        assert len(profiler.data['decorated']) == 1
        assert decorated(3) == 9
        assert len(profiler.data['decorated']) == 2


def test_profiler_stats():
    profiler = Profiler()
    profiler.data = {'test': [1.]}
    assert profiler.compute_stats() == \
        {'test': {'avg': 1., 'min': 1., 'max': 1., 'num': 1}}
    profiler.data = {'test': [1., 1., 1., 2.]}
    assert profiler.compute_stats() == \
        {'test': {'avg': 1.25, 'min': 1., 'max': 2., 'std': 0.5, 'num': 4}}
