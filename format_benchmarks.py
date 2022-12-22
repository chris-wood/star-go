import sys

def parse_name_to_params(line):
    # BenchmarkSTAR/(Aggregate-Feldman-VOPRF-32-1000-10000-1000)-12
    start = line.index("(")
    end = line.rindex(")")
    params = line[start+1:end].split("-")
    stage, agg, rand, input_len, input_count, sample_count, threshold = params[0], params[1], params[2], int(params[3]), int(params[4]), int(params[5]), int(params[6])
    return stage, agg, rand, input_len, input_count, sample_count, threshold

def ns_to_s(ns):
    return ns / 10**9

def parse_test_run(data):
    elements = data.strip().split("\t")
    name, runs, time, rate = elements[0], int(elements[1].strip()), ns_to_s(int(elements[2].strip().replace("ns/op",""))), int(float(elements[3].strip().replace("rate/op","")))
    stage, agg, rand, input_len, input_count, sample_count, threshold = parse_name_to_params(name)
    return stage, agg, rand, input_len, input_count, sample_count, threshold, runs, time, rate

basic_batch_costs = []
feldman_batch_costs = []
basic_stream_costs = []
feldman_stream_costs = []
for line in sys.stdin:
    line = line.strip()
    if line.startswith("BenchmarkSTAR/") and line.endswith("rate/op"):
        stage, agg, rand, input_len, input_count, sample_count, threshold, runs, time, rate = parse_test_run(line)
        if agg == "Basic" and stage == "PrepareAndAggregate":
            basic_batch_costs.append((sample_count, threshold, time))
        elif agg == "Basic" and stage == "Aggregate":
            basic_stream_costs.append((sample_count, threshold, time))
        elif agg == "Feldman" and stage == "PrepareAndAggregate":
            feldman_batch_costs.append((sample_count, threshold, time))
        elif agg == "Feldman" and stage == "Aggregate":
            feldman_stream_costs.append((sample_count, threshold, time))

print("basic_batch_costs = " + str(basic_batch_costs))
print("basic_stream_costs = " + str(basic_stream_costs))
print("feldman_batch_costs = " + str(feldman_batch_costs))
print("feldman_stream_costs = " + str(feldman_stream_costs))
