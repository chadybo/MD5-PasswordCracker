import csv
import hashlib
import sys
import time
from threading import Thread, Lock
from queue import Queue


def md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def generate_case_combinations(word):
    if len(word) == 0:
        return [""]

    first_char = word[0]
    rest_combinations = generate_case_combinations(word[1:])

    combinations = []

    for combination in rest_combinations:

        combinations.append(first_char.lower() + combination)
        combinations.append(first_char.upper() + combination)

    return combinations


def append_digits(combinations):
    digit_combinations = []

    for combo in combinations:
        for i in range(0, 10000):

            for zfill_len in range(1, 5):

                digit_combination = combo + str(i).zfill(zfill_len)
                digit_combinations.append(digit_combination)

    return digit_combinations


def replace_characters(combinations):
    replacements = {'e': '3', 'o': '0', 't': '7', 'E': '3', 'O': '0', 'T': '7'}
    replaced_combinations = []

    for combo in combinations:

        new_combo = ''.join(replacements.get(char, char) for char in combo)
        replaced_combinations.append(new_combo)

    return replaced_combinations


def process_single_password(dictionary, lock, results, thread_id, task_queue):

    while not task_queue.empty():
        with lock:
            if task_queue.empty():
                return

            username, hashed_password, salt = task_queue.get()

        for word in dictionary:

            combos = generate_case_combinations(word)
            combos2 = append_digits(combos)
            combos.extend(combos2)
            combos3 = replace_characters(combos2)
            combos.extend(combos3)

            for transformed in combos:

                concat = transformed.strip() + salt.strip()
                if md5_hash(concat) == hashed_password.strip():
                    with lock:
                        print(f"[Thread {thread_id}] Found password for {username}: {transformed}", flush=True)
                        results[username] = transformed
                    break
            else:
                continue
            break

        else:
            with lock:
                print(f"[Thread {thread_id}] Failed to crack password for {username}", flush=True)


def crack_passwords(password_db, dictionary):
    success_count = 0
    results = {}
    lock = Lock()
    task_queue = Queue()

    num_threads = 2

    for entry in password_db:
        task_queue.put(entry)

    threads = []
    for i in range(num_threads):

        thread = Thread(target=process_single_password, args=(dictionary, lock, results, i + 1, task_queue))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    for username, password_hash, salt in password_db:
        if username in results:
            success_count += 1
        else:
            results[username] = "FAILED"

    total_count = len(password_db)

    return results, success_count, total_count


def read_common_csv(file_path):
    pass_list = []

    with open(file_path, mode='r') as file:
        reader = csv.reader(file)

        for row in reader:
            password = row[0].strip()
            pass_list.append(password)

    return pass_list


def read_input_csv(file_path):
    hash_list = []

    with open(file_path, mode='r') as file:
        reader = csv.reader(file)

        for row in reader:

            username, password_hash, salt = row[0], row[1].strip(), row[2].strip()
            hash_list.append((username, password_hash, salt))

    return hash_list


def write_csv(file_path, cracked_passwords, total_time, success_rate, original_usernames):
    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)

        for username in original_usernames:
            if username in cracked_passwords:
                password = cracked_passwords[username]

                if password == "FAILED":
                    writer.writerow([password])
                else:
                    writer.writerow([username, f'{password}'])

        writer.writerow([f'{total_time}'])
        writer.writerow([f'{success_rate:.2f}'])


def main():
    start_time = time.time()

    hash_list = read_input_csv(sys.argv[1])
    output_file = "task5.csv"
    common_pass_list = read_common_csv("common_passwords.csv")

    cracked_passwords, success_count, total_count = crack_passwords(hash_list, common_pass_list)

    # print("THIS IS CRACKED_PASSWORDS: ", cracked_passwords)

    success_rate = (success_count / total_count) * 100

    end_time = time.time()
    total_time = round(end_time - start_time)

    original_usernames = [username for username, _, _ in hash_list]

    write_csv(output_file, cracked_passwords, total_time, success_rate, original_usernames)


if __name__ == "__main__":
    main()
