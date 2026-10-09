#### Meshtastic managed flooding, broadcasts (Meshtasticator)

| Nodes | Hop limit | Reach | Usefulness | Transmissions per message |
|---:|---:|---:|---:|---:|
| 10 | 1 | 57 % | 59 % | 2.7 |
| 10 | 3 | 75 % | 52 % | 4.3 |
| 10 | 5 | 79 % | 50 % | 4.9 |
| 10 | 7 | 77 % | 50 % | 4.8 |
| 25 | 1 | 43 % | 56 % | 3.4 |
| 25 | 3 | 58 % | 45 % | 6.4 |
| 25 | 5 | 61 % | 41 % | 7.8 |
| 25 | 7 | 62 % | 41 % | 8.2 |
| 50 | 1 | 31 % | 53 % | 3.8 |
| 50 | 3 | 37 % | 41 % | 7.1 |
| 50 | 5 | 37 % | 39 % | 8.2 |
| 50 | 7 | 38 % | 38 % | 8.7 |

#### Direct messages: Meshtastic (hop limit 3) vs Mycel's router, same topologies and messages

| Nodes | Links | Meshtastic delivered | Meshtastic tx per delivered | Mycel delivered | Mycel data tx per delivered | Mycel announcements per node per min | Mycel control traffic per node | Announcement airtime on LoRa LongFast |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 17 | 73 % | 5.7 | 100.0 % | 2.0 | 150 | 9 kbit/s | 723 % of the channel |
| 25 | 81 | 58 % | 10.2 | 99.9 % | 2.2 | 242 | 27 kbit/s | 1166 % of the channel |
| 50 | 239 | 39 % | 16.2 | 97.9 % | 2.9 | 284 | 50 kbit/s | 1366 % of the channel |
