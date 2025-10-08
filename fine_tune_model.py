import csv

with open("Finetuning_Data.csv", encoding="utf-8", newline="") as csvfile:
    csvreader = csv.reader(csvfile, delimiter=",")
    messages, code_snippets = [], []
    for row in csvreader:
        message, code = row
        messages.append(message)
        diffs = eval(code)
        deleted_tuples = diffs['deleted']
        deleted_lines = [del_tuple[1] for del_tuple in deleted_tuples]
        code_snippets.extend(deleted_lines)
    print(messages)
    print(code_snippets)

with open("Finetuning_Data_text.csv", mode="w", encoding="utf-8", newline="") as csvfile_out:
    writer = csv.DictWriter(csvfile_out, fieldnames=["training_text"])
    writer.writeheader()
    for message in messages:
        writer.writerow({"training_text": message})
    for code_snippet in code_snippets:
        writer.writerow({"training_text": code_snippet})







