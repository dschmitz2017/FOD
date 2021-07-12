curl -sS http://localhost:8000/api/routes/ -H Authorization:\ Token\ 1edfb21e52aa79c99ef3fcd5fea5d497ccd33d01 -X POST -H Content-Type:\ application/json -d \{\"name\":\"testrule1\"\,\ \"source\":\"0.0.0.0/0\"\,\ \"sourceport\":\"1000-2000\"\,\ \"destination\":\"12.11.10.9/32\"\,\ \"destinationport\":\"3000-4000\,5000-6000\"\,\ \"protocol\":\ \[\ \"udp\"\ \]\,\ \"status\":\"INACTIVE\"\,\ \"then\":\[\"rate-limit:10000k\"\]\,\ \"fragmenttype\":\[\ \"is-fragment\"\,\ \ \"first-fragment\"\]\,\ \"tcpflag\":\"\"\,\ \"expires\":\"2999-01-01\"\} 
Traceback (most recent call last):
  File "<string>", line 4, in <module>
KeyError: 'id'
rule-create failed
{
    "fragmenttype": [
        "Invalid hyperlink - No URL match."
    ]
}
