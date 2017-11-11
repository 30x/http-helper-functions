with open('/usr/share/dict/web2') as f:
    content = f.readlines()

    rslt = []
    i = 1
    while len(rslt) < 65536:
        rslt.extend([x for x in content if len(x) == i and x.lower() == x])
        i += 1
    rslt = rslt[:65535]

    with open('65536words', 'w') as f2:
        f2.writelines(rslt)
    

