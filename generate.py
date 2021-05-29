from random import randint
count = 2500
query_count = 5000
salaries = []
ranges = []

for _ in range(count):
    salaries.append(str(randint(2500, 16500)) + "\n")

for _ in range(query_count):
    small_int = randint(2500, 16500)
    big_int = randint(2500, 16500)
    if small_int > big_int:
        small_int, big_int = big_int, small_int
    
    ranges.append(str(small_int) + " " + str(big_int) + "\n")

with open('employees', 'w') as f:
    f.write(str(count) + "\n")
    f.writelines(salaries)
    f.write(str(query_count) + "\n")
    f.writelines(ranges)

