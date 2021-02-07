# Slowloris
This repo analyses the Slowloris attack in the CIC IDS 2017 dataset.

## Slowloris attack
The HTTP protocol (https://tools.ietf.org/html/rfc2616) specifies a (minimal) request as follows:
```
Request = Request-Line CRLF [ message-body ]
Request-Line = Method SP Request-URI SP HTTP-Version CRLF
```
A well formed request ends with a double `CRLF`. Slowloris holds connections to a web server open by sending HTTP requests
that don't terminate with a `CRLF`. Every request creates a new thread on the web server. Usually the number of threads a 
web server can handle is limited. If the maximum number of threads is reached, new requests to the server can't be 
processed anymore.

## CIC IDS 2017 dataset
A common dataset for intrusion detection is the CIC IDS 2017 dataset:
https://www.scitepress.org/Papers/2018/66398/66398.pdf
This dataset also contains a Slowloris attack.

For the analysis of the dataset the flow information and pcap files have been downloaded from
https://www.unb.ca/cic/datasets/ids-2017.html

In this dataset Slowloris attacks were performed on Wednesday between 9:47 – 10:10 a.m.
Therefore the flow information from this time interval was copied to the file `data/cic-data-0948-1010.csv`.

editcap was used to split the `Wednesday-WorkingHours.pcap` file into a smaller file:
```
editcap -A "2017-07-05 14:47:00" -B "2017-07-05 14:51:00" Wednesday-WorkingHours.pcap wednesday1447-1451.pcap
```

## Findings

### Typical Slowloris request
A Slowloris HTTP request in the CIC IDS 2017 dataset usually has the following characteristics:
* TCP window = 229
* TCP data offset = 8 
* Request doesn't terminate with `CRLF`

```
{'time': '5/7/2017 9:49', 'flow_id': '172.16.0.1-192.168.10.50-54192-80-6', 'num_packets': 7, 'label': 'DoS slowloris'}

                      time frame_number  sport  dport  window  dataofs  http crlf
0  2017-07-05 09:49:08        29542  54192     80   29200       10           
1  2017-07-05 09:49:08        29544     80  54192   28960       10           
2  2017-07-05 09:49:08        29545  54192     80     229        8           
3  2017-07-05 09:49:08        29546  54192     80     229        8  True     
4  2017-07-05 09:49:08        29548     80  54192     235        8           
5  2017-07-05 09:50:01        59019  54192     80     229        8  True     
6  2017-07-05 09:50:01        59031     80  54192     235        8   
```

### 2: Slowloris attack without HTTP request
Not all flows labeled as a Slowloris attack contain a HTTP request:
```
{'time': '5/7/2017 9:49', 'flow_id': '172.16.0.1-192.168.10.50-54776-80-6', 'num_packets': 3, 'label': 'DoS slowloris'}

                  time frame_number  sport  dport  window  dataofs http crlf
0  2017-07-05 09:49:42        52441  54776     80   29200       10          
1  2017-07-05 09:49:43        53168  54776     80   29200       10          
2  2017-07-05 09:49:45        54505  54776     80   29200       10        
```


### 3: Two Slowloris attacks with same timestamp and flow id
In some cases two attacks have the same timestamp and flow id. The following flows don't look like they are related to a
Slowloris attack:

```
{'time': '5/7/2017 9:49', 'flow_id': '172.16.0.1-192.168.10.50-54114-80-6', 'num_packets': 25, 'label': 'DoS slowloris'}
{'time': '5/7/2017 9:49', 'flow_id': '172.16.0.1-192.168.10.50-54114-80-6', 'num_packets': 2, 'label': 'DoS slowloris'}

                   time frame_number  sport  dport  window  dataofs  http  crlf
0   2017-07-05 09:49:01        25428  54114     80   29200       10            
1   2017-07-05 09:49:01        25429     80  54114   28960       10            
2   2017-07-05 09:49:01        25430  54114     80     229        8            
3   2017-07-05 09:49:02        25461  54114     80     229        8  True  True
4   2017-07-05 09:49:02        25468  54114     80     229        8  True  True
5   2017-07-05 09:49:02        25503  54114     80     229        8  True  True
6   2017-07-05 09:49:03        25523  54114     80     229        8  True  True
7   2017-07-05 09:49:03        25524     80  54114     235        8            
8   2017-07-05 09:49:13        33244  54114     80     229        8            
9   2017-07-05 09:49:13        33245     80  54114     235        8            
10  2017-07-05 09:49:13        33278     80  54114     235        8  True  True
11  2017-07-05 09:49:13        33279     80  54114     235        8  True      
12  2017-07-05 09:49:13        33280     80  54114     235        8  True      
13  2017-07-05 09:49:13        33281  54114     80     274        8            
14  2017-07-05 09:49:13        33282  54114     80     296        8            
15  2017-07-05 09:49:13        33286  54114     80     296        8  True  True
16  2017-07-05 09:49:13        33287     80  54114     243        8            
17  2017-07-05 09:49:13        33288     80  54114     243        8  True  True
18  2017-07-05 09:49:13        33289     80  54114     243        8  True      
19  2017-07-05 09:49:13        33290  54114     80     342        8            
20  2017-07-05 09:49:13        33291  54114     80     364        8            
21  2017-07-05 09:49:13        33301  54114     80     364        8  True  True
22  2017-07-05 09:49:13        33312     80  54114     252        8  True  True
23  2017-07-05 09:49:13        33317  54114     80     387        8            
24  2017-07-05 09:49:18        33707     80  54114     252        8            
25  2017-07-05 09:49:18        33708  54114     80     387        8            
26  2017-07-05 09:49:18        33710     80  54114     252        8 
```

### 4: One flow id with different labels
One flow id with one timestamp can have multiple labels. Flow number 21934 looks like a Slowloris attack.

```
{'time': '5/7/2017 9:48', 'flow_id': '172.16.0.1-192.168.10.50-53418-80-6', 'num_packets': 2, 'label': 'BENIGN'}
{'time': '5/7/2017 9:48', 'flow_id': '172.16.0.1-192.168.10.50-53418-80-6', 'num_packets': 6, 'label': 'DoS slowloris'}


                  time frame_number  sport  dport  window  dataofs  http  crlf
0  2017-07-05 09:48:46        21931  53418     80   29200       10            
1  2017-07-05 09:48:46        21932     80  53418   28960       10            
2  2017-07-05 09:48:46        21933  53418     80     229        8            
3  2017-07-05 09:48:46        21934  53418     80     229        8  True      
4  2017-07-05 09:48:46        21936     80  53418     235        8            
5  2017-07-05 09:48:46        22801  53418     80     229        8            
6  2017-07-05 09:48:46        23192     80  53418     235        8  True  True
7  2017-07-05 09:48:46        23193     80  53418     235        8            
8  2017-07-05 09:48:46        23201  53418     80       0        5     
```