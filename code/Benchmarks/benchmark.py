import time, os, sys, csv

TARGET = '../mount/benchmark1.txt'

ONE_KB = 1000
ONE_MB = 1000 * ONE_KB
S_FILE = 100 * ONE_KB
M_FILE = 1 * ONE_MB
L_FILE = 10 * ONE_MB
XL_FILE = 20 * ONE_MB



def write_file(path, max_size, block_size=4096):
    size = 0
    block_buff = 'A'*block_size
    extra_buff = 'A'*(max_size%block_size)
    block_times = []
    with open(path, 'w') as file:
        for i in range(block_size, max_size, block_size):
            start = time.time()
            file.write(block_buff)
            block_times.append(time.time() - start)
        file.write(extra_buff)
    return block_times

def override_at_offset(path, offset):
    with open(path, 'r+b') as file:
        file.seek(offset)
        file.write('BBBB'.encode('ascii'))



def write_to_csv(path, x_title, y_title, x_axis, y_axis):
    with open(path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([x_title, y_title])
        for i in range(len(x_axis)):
            writer.writerow([x_axis[i], y_axis[i]])



def per_block_test(prefix):
    block_times = write_file(TARGET, XL_FILE)
    write_to_csv(f'results/{prefix}_per_block_time.csv', 'Block index',
        'Time [s]', [i for i in range(len(block_times))], block_times)


def per_size_test(prefix, max_iteration=100, max_seconds=180):
    sizes = [S_FILE, M_FILE, L_FILE, XL_FILE]
    file_times = []
    for file_size in sizes:
        elapsed = 0; iteration = 0
        full_start = time.time()
        while time.time() - full_start < max_seconds and iteration < max_iteration:
            start = time.time()
            write_file(TARGET, file_size)
            elapsed += time.time() - start
            iteration += 1
        file_times.append(elapsed/iteration)
    write_to_csv(f'results/{prefix}_per_size_time.csv', 'File Size [B]',
            'Time [s]', sizes, file_times)


def per_block_size_test(prefix, max_iteration=100, max_seconds=60):
    block_sizes = [ONE_KB, 10*ONE_KB, 50*ONE_KB, 100*ONE_KB]
    block_size_times = []
    for block_size in block_sizes:
        elapsed = 0; iteration = 0
        full_start = time.time()
        while time.time() - full_start < max_seconds and iteration < max_iteration:
            start = time.time()
            write_file(TARGET, L_FILE, block_size)
            elapsed += time.time() - start
            iteration += 1
        block_size_times.append(elapsed/iteration)
    write_to_csv(f'results/{prefix}_per_block_size_time.csv', 'Block Size [B]',
            'Time [s]', block_sizes, block_size_times)


def per_file_count_test(prefix):
    number_files = [1, 10, 50, 100]
    number_files_times = []
    for number_file in number_files:
        elapsed = 0;
        for i in range(number_file):
            start = time.time()
            write_file(TARGET+str(i), M_FILE)
            elapsed += time.time() - start
        number_files_times.append(elapsed/number_file)
    write_to_csv(f'results/{prefix}_per_file_count_time.csv', 'Number of files',
            'Time [s]', number_files, number_files_times)


def per_offset_write_test(prefix):
    write_file(TARGET, XL_FILE)
    offset_pos = []
    offset_pos_times = []
    for offset in range(0, XL_FILE, XL_FILE//100):
        start = time.time()
        override_at_offset(TARGET, offset)
        offset_pos_times.append(time.time() - start)
        offset_pos.append(offset)
    write_to_csv(f'results/{prefix}_per_offset_write_time.csv', 'Offset position [B]',
            'Time [s]', offset_pos, offset_pos_times)


def per_folder_depth_test(prefix, max_iteration=20, max_seconds=60):
    per_folder_depth_times = []
    depths = [1, 5, 10, 50, 100]
    for i in [1, 5, 10, 50, 100]:
        path = '../mount'
        for j in range(i):
            path += '/dir' + str(j)
            try:
                if not os.path.exists(path):
                    os.mkdir(path)
            except OSError:
                print ("Creation of the directory %s failed" % path)

        elapsed = 0; iteration = 0
        full_start = time.time()
        while time.time() - full_start < max_seconds and iteration < max_iteration:
            start = time.time()
            write_file(path+'/benchmark1.txt', S_FILE)
            elapsed += time.time() - start
            iteration += 1
        per_folder_depth_times.append(elapsed/iteration)
    write_to_csv(f'results/{prefix}_per_folder_depth_time.csv', 'Folder depth',
            'Time [s]', depths, per_folder_depth_times)



if __name__ == '__main__':
    if len(sys.argv) > 3:
        TARGET = sys.argv[3]
    if sys.argv[1] == 'PER_BLOCK':
        per_block_test(sys.argv[2])
    elif sys.argv[1] == 'PER_SIZE':
        per_size_test(sys.argv[2])
    elif sys.argv[1] == 'PER_BLOCK_SIZE':
        per_block_size_test(sys.argv[2])
    elif sys.argv[1] == 'PER_FILE_COUNT':
        per_file_count_test(sys.argv[2])
    elif sys.argv[1] == 'PER_OFFSET_WRITE':
        per_offset_write_test(sys.argv[2])
    elif sys.argv[1] == 'PER_FOLDER_DEPTH':
        per_folder_depth_test(sys.argv[2])
