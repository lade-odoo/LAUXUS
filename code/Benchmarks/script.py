import matplotlib.pyplot as plt
import pandas as pd


# PER BLOCK SIZE #
l_df = pd.read_csv('results/LAUXUS_per_block_size_time.csv'); l_df['Block Size [KB]'] = l_df['Block Size [B]'].div(1000)
n_df = pd.read_csv('results/NOTHING_per_block_size_time.csv'); n_df['Block Size [KB]'] = n_df['Block Size [B]'].div(1000)
p_df = pd.read_csv('results/PASSTHROUGH_per_block_size_time.csv'); p_df['Block Size [KB]'] = p_df['Block Size [B]'].div(1000)

ax = l_df.plot(x='Block Size [KB]', y='Time [s]', style='-.r', label='LAUXUS')
n_df.plot(ax=ax, x='Block Size [KB]', y='Time [s]', style='-.c', label='ext4')
p_df.plot(ax=ax, x='Block Size [KB]', y='Time [s]', style='-.b', label='FUSE passthrough')

plt.xlabel('Block Size [KB]')
plt.ylabel('Time [s]')
plt.legend()
plt.savefig('charts/per_block_size.png')


# PER BLOCK #
l_df = pd.read_csv('results/LAUXUS_per_block_time.csv'); l_df['Time [us]'] = l_df['Time [s]'].mul(1000*1000); l_df = l_df[l_df['Time [us]'] > 200].dropna()
n_df = pd.read_csv('results/NOTHING_per_block_time.csv'); n_df['Time [us]'] = n_df['Time [s]'].mul(1000*1000)
p_df = pd.read_csv('results/PASSTHROUGH_per_block_time.csv'); p_df['Time [us]'] = p_df['Time [s]'].mul(1000*1000); p_df = p_df[p_df['Time [us]'] > 20].dropna()

ax = l_df.plot(x='Block index', y='Time [us]', style='-.r', label='LAUXUS')
n_df.plot(ax=ax, x='Block index', y='Time [us]', style='-.c', label='ext4')
p_df.plot(ax=ax, x='Block index', y='Time [us]', style='-.b', label='FUSE passthrough')

plt.xlabel('Block Index')
plt.ylabel('Time [us]')
plt.legend()
plt.savefig('charts/per_block.png')


# PER FOLDER DEPTH #
l_df = pd.read_csv('results/LAUXUS_per_folder_depth_time.csv'); l_df['Time [ms]'] = l_df['Time [s]'].mul(1000)
n_df = pd.read_csv('results/NOTHING_per_folder_depth_time.csv'); n_df['Time [ms]'] = n_df['Time [s]'].mul(1000)
p_df = pd.read_csv('results/PASSTHROUGH_per_folder_depth_time.csv'); p_df['Time [ms]'] = p_df['Time [s]'].mul(1000)

ax = l_df.plot(x='Folder depth', y='Time [ms]', style='-.r', label='LAUXUS')
n_df.plot(ax=ax, x='Folder depth', y='Time [ms]', style='-.c', label='ext4')
p_df.plot(ax=ax, x='Folder depth', y='Time [ms]', style='-.b', label='FUSE passthrough')

plt.xlabel('Folder depth')
plt.ylabel('Time [ms]')
plt.legend()
plt.savefig('charts/per_folder_depth.png')


# PER FOLDER DEPTH #
l_df = pd.read_csv('results/LAUXUS_per_file_size_small_write_time.csv'); l_df['Time [us]'] = l_df['Time [s]'].mul(1000*1000); l_df['File Size [MB]'] = l_df['File Size [B]'].div(1000*1000)
n_df = pd.read_csv('results/NOTHING_per_file_size_small_write_time.csv'); n_df['Time [us]'] = n_df['Time [s]'].mul(1000*1000); n_df['File Size [MB]'] = n_df['File Size [B]'].div(1000*1000)
p_df = pd.read_csv('results/PASSTHROUGH_per_file_size_small_write_time.csv'); p_df['Time [us]'] = p_df['Time [s]'].mul(1000*1000); p_df['File Size [MB]'] = p_df['File Size [B]'].div(1000*1000)

ax = l_df.plot(x='File Size [MB]', y='Time [us]', style='-.r', label='LAUXUS')
n_df.plot(ax=ax, x='File Size [MB]', y='Time [us]', style='-.c', label='ext4')
p_df.plot(ax=ax, x='File Size [MB]', y='Time [us]', style='-.b', label='FUSE passthrough')

plt.xlabel('File Size [MB]')
plt.ylabel('Time [us]')
plt.legend()
plt.savefig('charts/per_file_size_small_write.png')


# PER OFFSET WRITE #
l_df = pd.read_csv('results/LAUXUS_per_offset_write_time.csv')
n_df = pd.read_csv('results/NOTHING_per_offset_write_time.csv')
p_df = pd.read_csv('results/PASSTHROUGH_per_offset_write_time.csv')

ax = l_df.plot(x='Offset position [B]', y='Time [s]', style='-.r', label='LAUXUS')
n_df.plot(ax=ax, x='Offset position [B]', y='Time [s]', style='-.c', label='ext4')
p_df.plot(ax=ax, x='Offset position [B]', y='Time [s]', style='-.b', label='FUSE passthrough')

plt.xlabel('Offset position [B]')
plt.ylabel('Time [s]')
plt.legend()
plt.savefig('charts/per_offset_write.png')


# PER SIZE #
l_df = pd.read_csv('results/LAUXUS_per_size_time.csv'); l_df['File Size [MB]'] = l_df['File Size [B]'].div(1000*1000)
n_df = pd.read_csv('results/NOTHING_per_size_time.csv'); n_df['File Size [MB]'] = n_df['File Size [B]'].div(1000*1000)
p_df = pd.read_csv('results/PASSTHROUGH_per_size_time.csv'); p_df['File Size [MB]'] = p_df['File Size [B]'].div(1000*1000)
r_df = p_df; r_df['Ratio'] = l_df['Time [s]']/n_df['Time [s]']

fig, ax1 = plt.subplots()
ax2 = ax1.twinx()
l_df.plot(ax=ax1, x='File Size [MB]', y='Time [s]', style='-.r', label='LAUXUS')
n_df.plot(ax=ax1, x='File Size [MB]', y='Time [s]', style='-.c', label='ext4')
p_df.plot(ax=ax1, x='File Size [MB]', y='Time [s]', style='-.b', label='FUSE passthrough')
r_df.plot(ax=ax2, x='File Size [MB]', y='Ratio', style='-g', label='Ratio LAUXUS VS ext4')

ax1.set_xlabel('File Size [MB]')
ax1.set_ylabel('Time [s]')
ax2.set_ylabel('Ratio')
plt.legend()
plt.savefig('charts/per_size.png')


# OTHER USAGE - Manually measured #
data = {'File Size':  [0, 0.9, 5, 11, 18.7],
        'Stack peak': [7, 18, 79, 155, 232],
        'Heap peak': [36, 64, 172, 304, 436],
        'CPU': [0, 0.9, 5, 11, 18.7],
        }
df = pd.DataFrame(data, columns = ['File Size', 'Stack peak', 'Heap peak', 'CPU'])

fig, ax1 = plt.subplots()
ax2 = ax1.twinx()
df.plot(ax=ax1, x='File Size', y='Stack peak', style='-.r', label='Stack peak')
df.plot(ax=ax1, x='File Size', y='Heap peak', style='-.b', label='Heap peak')
df.plot(ax=ax2, x='File Size', y='CPU', style='-g', label='CPU usage', legend=False)

ax1.set_xlabel('File Size [MB]')
ax1.set_ylabel('Memory Usage [KB]')
ax2.set_ylabel('CPU Usage [%]')
h1, l1 = ax1.get_legend_handles_labels()
h2, l2 = ax2.get_legend_handles_labels()
ax1.legend(h1+h2, l1+l2, loc=2)
plt.savefig('charts/memory_cpu_usage.png')
