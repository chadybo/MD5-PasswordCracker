import hashlib
import time
import csv
import sys
from collections import defaultdict


def md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def read_input_csv(file_path):
    hash_list = []

    with open(file_path, mode='r') as file:
        reader = csv.reader(file)

        for row in reader:

            username, password_hash = row[0], row[1].strip()
            hash_list.append((username, password_hash))

    return hash_list


def read_common_csv(file_path):
    pass_list = []

    with open(file_path, mode='r') as file:
        reader = csv.reader(file)

        for row in reader:

            password = row[0].strip()
            pass_list.append(password)

    return pass_list


def dictionary_attack(hash_list, common_pass_list):
    cracked_passwords = defaultdict(set)
    successful_usernames = set()

    for username, hashed_password in hash_list:
        for common_pass in common_pass_list:

            hashed_common_pass = md5_hash(common_pass)
            if hashed_password == hashed_common_pass:

                cracked_passwords[username].add(common_pass)
                successful_usernames.add(username)

    total_usernames = len(hash_list)

    # print("THIS IS TOTAL_USERNAMES: ", total_usernames)
    # print("THIS IS SUCCESSFUL_USERNAMES: ", len(successful_usernames))
    # print(successful_usernames)
    success_rate = (len(successful_usernames)/total_usernames) * 100

    for username, password_hash in hash_list:
        if username not in cracked_passwords:
            cracked_passwords[username].add("FAILED")

    return cracked_passwords, success_rate


def write_csv(file_path, cracked_passwords, total_time, success_rate, original_usernames):
    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)

        for username in original_usernames:
            if username in cracked_passwords:
                password = ' '.join(cracked_passwords[username])

                if password == "FAILED":
                    writer.writerow([password])
                else:
                    writer.writerow([username, f'{password}'])

        writer.writerow([f'{total_time}'])
        writer.writerow([f'{success_rate:.2f}'])


def main():
    start_time = time.time()

    input_file = sys.argv[1]
    output_file = 'task2.csv'
    hash_list = read_input_csv(input_file)
    common_pass_list = read_common_csv("common_passwords.csv")

    cracked_passwords, success_rate = dictionary_attack(hash_list, common_pass_list)

    end_time = time.time()
    total_time = round(end_time - start_time)

    # print("THIS IS CRACKED PASSWORDS: ", cracked_passwords)
    original_usernames = [username for username, _ in hash_list]

    write_csv(output_file, cracked_passwords, total_time, success_rate, original_usernames)

    # print("THIS IS THE CRACKED_PASSWORDS: ", cracked_passwords)
    # print("THIS IS THE SUCCESS RATE: ", success_rate)

    # print("THIS IS HASHLIST: ", hash_list)
    # print("THIS IS COMMON_PASS_LIST: ", common_pass_list)


if __name__ == '__main__':
    main()