import json

name = "24"

with open(f"static/{name}.json", "r") as fopen:
    data = json.load(fopen)
    print(data[0])
    sorted_data = sorted(data, key=lambda x: -x['vote_count'])
    count = 1
    for item in sorted_data:
        item['id'] = count
        count += 1

with open(f"static/{name}_sorted.json", "w") as fopen:
    json.dump(sorted_data, fopen, indent=4)
