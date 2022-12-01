from pwn import *
import sys

def disasm_data(seg):
    data=seg.data()
    offset=seg.header.p_vaddr
    asm_data=disasm(data,byte=0,vma=offset).splitlines()
    asm_code=[]
    for i in asm_data:
        split_ind=i.find(':')
        off=i[:split_ind]
        code=i[split_ind+1:]
        end_ind=code.rfind('#')
        if end_ind!=-1:
            code=code[:end_ind]
        code=code.strip()
        off=int(off,16)
        asm_code.append([off,code])
    return asm_code


def get_segment(e):
    exec_code={}
    segment_l=e.segments
    for i in segment_l:
        if i.header.p_flags&1 :
            exec_code[i]=disasm_data(i)
    return exec_code

def get_out_code(code,sear_str="",out_lines=1):
    out_data=[]
    i=0
    code_num=len(code)
    while i<code_num:
        if sear_str in code[i][1]:
            data=' ; '.join([j[1] for j in code[i:i+out_lines]])
            out_data.append([code[i][0],data])
        i+=1
    return out_data


def helper():
    print("""usage: sear_asm [-h] [-c <string>] [-i <int>]
    -h/--help  get help
    -c/--code  search code,There can be multiple
    -i         Number of display codes

    -s/--save  Whether to save the code file
    -q/--quiet Whether quiet execution is required""")

def error(out_data,reas):
    helper()
    print("%s , reason: %s"%(out_data,reas))
    exit(0)

def parse_arg():
    argv=sys.argv
    if (argv.count('-h') != 0 or argv.count('--help') != 0):
        helper()
        exit(0)
    i=0
    codes=[]
    num=1
    other_arg=[]
    is_Save=False
    is_Display=True
    while i<len(argv):
        try:
            if argv[i]=='-c' or argv[i]=='--code':
                codes.append(argv[i+1])
                i=i+1
            elif argv[i]=='-i':
                num=int(argv[i+1])
                i=i+1
            elif argv[i]=='-s' or argv[i]=='--save':
                is_Save=True
            elif argv[i]=='-q' or argv[i]=='--quiet':
                is_Display=False
            else:
                other_arg.append(argv[i])
            i+=1
        except:
            error("Parse Option Error",argv[i])
    if num<1:
        error("This will not display the code","%s < 1"%num)
    if codes==[]:
        codes=[""]
    return other_arg,num,codes,is_Save,is_Display

def parse_file(filename,s_code,num):
    pri_arch=context.arch
    try:
        e=ELF(filename,checksec=0)
    except:
        return 0
    context.arch=e.arch
    segs=get_segment(e)
    code_l=[]
    for i in segs:
        num_c=num
        codes=segs[i]
        for j in s_code:
            codes=get_out_code(codes,j,num_c)
            num_c=1
        code_l.append(codes)
    context.arch=pri_arch
    return [filename,code_l]

def save_file_code(f_code):
    f=open('%s.asm'%f_code[0],'w')
    for i in f_code[1]:
        for j in i:
            f.write("0x%016x : %s\n"%(j[0],j[1]))
    f.close()
    print("----------   save:%s:ok -----------"%f_code[0])

def out_file_code(f_code):
    print("----------    %s:asm    ----------"%f_code[0])
    for i in f_code[1]:
        for j in i:
            print("0x%016x : %s"%(j[0],j[1]))
    print("----------    end   ----------")

def main():
    file_l,num,s_code,is_Save,is_Display=parse_arg()
    f_codes=[]
    for i in file_l:
        f_code=parse_file(i,s_code,num)
        if f_code!=0:
            if is_Save:
                save_file_code(f_code)
            if is_Display:
                out_file_code(f_code)




if __name__=='__main__':
    main()
    exit(0)
