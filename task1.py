import hashlib
import itertools
import time
import csv
import sys
from collections import defaultdict


def md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def brute_force_crack(hash_list):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    max_length = 4
    cracked_passwords = defaultdict(set)
    successful_usernames = set()

    for length in range(1, max_length + 1):
        for guess in itertools.product(chars, repeat=length):
            guess = ''.join(guess)
            hashed_guess = md5_hash(guess)

            for username, password_hash in hash_list:
                if hashed_guess == password_hash:
                    
                    cracked_passwords[username].add(guess)
                    successful_usernames.add(username)

    total_usernames = len(hash_list)

    # print("THIS IS LEN OF HASH_LIST: ", total_usernames)
    # print("THIS IS LEN OF SUCCESFUL USERNAMES: ", len(successful_usernames))
    success_rate = (len(successful_usernames) / total_usernames) * 100

    for username, password_hash in hash_list:
        if username not in cracked_passwords:
            cracked_passwords[username].add("FAILED")

    return cracked_passwords, success_rate


def read_csv(file_path):
    hash_list = []

    with open(file_path, mode='r') as file:
        reader = csv.reader(file)

        for row in reader:
            username, password_hash = row[0], row[1].strip()
            hash_list.append((username, password_hash))

    return hash_list


def write_csv(file_path, cracked_passwords, total_time, success_rate, original_usernames):
    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)

        for username in original_usernames:
            if username in cracked_passwords:
                password = ' '.join(cracked_passwords[username])
                # print("THIS IS THE PASSWORD: ", password)

                if password == "FAILED":
                    writer.writerow([password])
                else:
                    writer.writerow([username, f'{password}'])

        writer.writerow([f'{total_time}'])
        writer.writerow([f'{success_rate:.2f}'])


def main():
    start_time = time.time()

    input_file = sys.argv[1]
    output_file = 'task1.csv'
    hash_list = read_csv(input_file)

    # print("THIS IS THE HASH_LIST: ", hash_list)
    original_usernames = [username for username, _ in hash_list]
    cracked_passwords, success_rate = brute_force_crack(hash_list)

    # print("THIS IS CRACKED PASSWORDS IN MAIN: ", cracked_passwords)
    # print("THIS IS ORIGINAL USERNAMES IN MAIN: ", original_usernames)

    end_time = time.time()
    total_time = round(end_time - start_time)

    write_csv(output_file, cracked_passwords, total_time, success_rate, original_usernames)


if __name__ == '__main__':
    main()

