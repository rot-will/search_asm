使用PWNtools制作的，用来搜索程序中的指令<br>
因为使用ROPgadget，无法搜索正常函数中的代码，而有些可以利用的指令就在正常的程序中<br>


usage: sear_asm [-h] [-c <string>] [-i <int>]<br>
 -h/--help  get help<br>
    -c/--code  search code,There can be multiple<br>
    -i         Number of display codes<br>
    -s/--save  Whether to save the code file<br>
    -q/--quiet Whether quiet execution is required<br>