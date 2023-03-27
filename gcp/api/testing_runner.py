import subprocess
import json
import timeit

success_count = 0
fail_count = 0

acc_time = 0

for x in range(100):
  start_time = timeit.default_timer()
  output = subprocess.check_output('./grpc_cmd.sh', shell=True)
  obj = json.loads(output.decode('utf-8'))

  if obj['matches'][-2]['score'] != 1 or obj['matches'][-1]['score'] != 1:
    fail_count += 1
  else:
    success_count += 1

  end_time = timeit.default_timer()

  acc_time += end_time - start_time

  print(
      f'success: {success_count}, fail: {fail_count}, current_time: {end_time - start_time}, current_avg: {acc_time / (success_count + fail_count)}'
  )

print(success_count)
print(fail_count)
