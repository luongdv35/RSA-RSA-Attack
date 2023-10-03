# RSA-RSA-Attack
<a href="https://github.com/404"><img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%"></a>

# **1.Tổng quan RSA**
- RSA thuộc nhóm hệ mã khóa công khai, dựa vào độ khó của bài toán phân tích 1 số ra thừa số nguyên tố (factoring problem). Để tạo cặp khóa Public key và Private key, Alice cần:
      - Chọn 2 số nguyên tố lớn p, q với p ≠ q
      - Tính n = pq
      - Tính giá trị hàm số Ơle φ(n) = (p-1)(q-1)
      - Chọn 1 số e sao cho 1 < e < φ(n) và gcd(e,φ(n)) = 1
      - Tính d = e-1 (mod φ(n)), số d thỏa mãn ed ≡ 1 (mod φ(n))
 
 - Public Key gồm:
      - n – module.
      - e – số mũ mã hóa
 
 - Private Key gồm:
      - n – module.
      - d – số mũ giải mã.
 
 
 - Khi Bob muốn gửi một tin nhắn M cho Alice, Bob chuyển M thành một số m < n theo 1 cách thỏa thuận trước. Bob sẽ tính ra bản mã c từ bản rõ m theo công thức:
  
   ``c = m ^ e (mod n)`` 

 - Để giải mã, Alice dùng Private Key của mình để tính ngược lại:
  
   ``m = c ^ d (mod n)``
 - Quá trình giải mã có thể thu lại được m ban đầu là do:

   ``c ^ d ≡ (m ^ e) ^ d ≡ m ^ ed (mod n) ≡ m (mod n) hay m = c ^ d (mod n)``
 - Dấu ≡ cuối cùng là tôi đã áp dụng [``định lý Euler``](https://vi.wikipedia.org/wiki/%C4%90%E1%BB%8Bnh_l%C3%BD_Euler). Chi tiết hơn về thiết kế hệ mã cũng như ví dụ có thể đọc ở đây [``RSA – Wikipedia``](https://vi.wikipedia.org/wiki/RSA_(m%C3%A3_h%C3%B3a))

 - Độ mạnh của hệ mã RSA dựa trên việc bạn cần phân tích được n ra thừa số nguyên tố để tính d nếu muốn phá mã, và đến nay chưa có giải thuật nào hiệu quả trong thời gian đa thức giúp ta phân tích thừa số nguyên tố đối với các số lớn.

 - Hệ mã RSA nếu được thiết kế một cách đúng đắn với việc chọn các tham số n, p, q, e hợp lý thì sẽ rất an toàn, thế nhưng trong các bài CTF, các tham số này thường được chọn theo một cách nào đó khiến cho hệ mã yếu đi và dễ bị tấn công. Các điểm yếu thực thi của RSA sẽ được trình bày dưới đây.

<a href="https://github.com/404"><img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" width="100%"></a>
  
<p align="center"><a href="https://github.com/a3x3k"><img src="https://user-images.githubusercontent.com/41234408/101987287-302ffe00-3cb9-11eb-8510-3d08f56bea27.gif" alt="Animated footer bars" width="100%"/></a></p>  

# **2.RSA Attack**
## 1.Small n
- Nếu n nhỏ (chiều dài n < 256 bit), ta có thể dễ dàng factorize n bằng cách brute-force số p. Chiều dài n được khuyến cáo là 1024 bit.

- Kể cả khi n lớn, đôi khi factorize của n đã có sẵn trong các database online như [factordb](http://factordb.com/). Hoặc dễ dàng factorize bằng các công cụ online như [alpertron](https://www.alpertron.com/), trang web này sử dụng phương pháp Elliptic Curve Method để factorize. Vậy nên, việc đầu tiên bạn cần làm khi gặp các bài RSA là thử các trang web này trước.
- Code minh họa:
```python
from Crypto.Util.number import inverse, long_to_bytes
from factordb.factordb import FactorDB

n = 742449129124467073921545687640895127535705902454369756401331
e = 3
ct = 39207274348578481322317340648475596807303160111338236677373

f = FactorDB(n)
f.connect()
[p, q] =(f.get_factor_list())

phi =(p-1)*(q-1)
d = inverse(e,phi)
decrypted = pow(ct,d,n)
print(long_to_bytes(decrypted))
```
## 2.Small e, small m
- Trong sử dụng RSA làm phương thức truyền tin. Khi chúng ta chọn p và q là số nguyên tố lớn và mạnh ⇒ n là số rất lớn. Nhưng ta chọn 1 số e nhỏ vd như e = 3. Và gửi một đoạn tin nhắn nhỏ (small m)

- Chúng ta sẽ tính được bản mã như sau:

- c = m^e (mod n)

- Nhưng bởi vì e và m rất nhỏ ⇒ m^e < n nên bản mã không bị ảnh hưởng bởi modulo.

- ⇒ c = m^e

- Vậy ta chỉ cần căn bậc e bản mã thì sẽ thu được bản rõ.
- Code minh họa:
```python
from Crypto.Util.number import long_to_bytes
import gmpy2

n = 17258212916191948536348548470938004244269544560039009244721959293554822498047075403658429865201816363311805874117705688359853941515579440852166618074161313773416434156467811969628473425365608002907061241714688204565170146117869742910273064909154666642642308154422770994836108669814632309362483307560217924183202838588431342622551598499747369771295105890359290073146330677383341121242366368309126850094371525078749496850520075015636716490087482193603562501577348571256210991732071282478547626856068209192987351212490642903450263288650415552403935705444809043563866466823492258216747445926536608548665086042098252335883
e = 3
ct = 243251053617903760309941844835411292373350655973075480264001352919865180151222189820473358411037759381328642957324889519192337152355302808400638052620580409813222660643570085177957
flag = gmpy2.iroot(ct,3)[0]
print(long_to_bytes(flag))
```
## 3.Fermat Attack
- Trong thực tế, ta cần chọn p, q có cùng độ dài bit để tạo được 1 mã RSA mạnh, tuy nhiên nếu p, q quá gần nhau thì lại tạo ra lỗ hổng bảo mật khi mà attacker có thể dễ dàng factorize n
- Trong thực tế nếu: p - q < n^(1/4) thì Fermat’s factoring algorithm có thể phân tích n 1 cách hiệu quả.
- Ta có : ![](https://hackmd.io/_uploads/rySj8R192.png)
- Với``x = (p - q)/2`` & ``y = (p + q)/2``
- n có thể được phân tích thừa số nguyên tố như sau: 
``n = x^2 - y^2 = (x - y)(x + y)``
- Định lý Fermat giúp tìm p, q
- ![](https://hackmd.io/_uploads/SyeNAPR1c2.png)
- Code minh họa:
```python
def isqrt(n):
    x = n
    y = (x + n // x) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def fermat(n):
    a = isqrt(n)
    b2 = a*a - n
    b = isqrt(n)
    count = 0
    while b*b != b2:
        a = a + 1
        b2 = a*a - n
        b = isqrt(b2)
        count += 1
    p = a+b
    q = a-b
    assert n == p * q
    return p, q


def main():
    n = 163325259729739139586456854939342071588766536976661696628405612100543978684304953042431845499808366612030757037530278155957389217094639917994417350499882225626580260012564702898468467277918937337494297292631474713546289580689715170963879872522418640251986734692138838546500522994170062961577034037699354013013
    p, q = fermat(n)
    print p
    print q
    

if __name__ == '__main__':
    main()
```
## 4.Hastad Broadcast Attack
- Đặt bối cảnh một mạng nội bộ sử dụng RSA làm phương thức bảo mật truyền tin. Mỗi máy tính trong mạng LAN sẽ có một bộ Public Key (ni, ei) riêng. Giả sử rằng, quản trị viên muốn sử dụng hệ thống mã hóa đơn giản nên anh ta chọn 1 số e nhỏ (e = 3) để dùng chung cho tất cả các máy trong mạng LAN, hay nói cách khác e1 = e2 = en = e = 3.
- Kịch bản tấn công xảy ra nếu máy chủ gửi cùng 1 tin nhắn broadcast m (đã được mã hóa thành c1, c2, ... cho nhiều máy tính trong mạng, và ta bắt được ít nhất e ciphertext c1, c2, ..., ce. Lúc này, ta sẽ có thể khôi phục lại plaintext m không mấy khó khăn.
- Giả sử e = 3, đặt M = m3. Nhiệm vụ của ta là giải hệ phương trình đồng dư: ![](https://hackmd.io/_uploads/Skmk9Akch.png)
- Ta có thể áp dụng [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem#:~:text=In%20mathematics%2C%20the%20Chinese%20remainder,are%20pairwise%20coprime%20(no%20two)). Sau khi tính được M, ta sẽ tìm lại được m (vì m < ni nên M = m3 < N, ta chỉ cần tính căn bậc 3 của M).
- Code minh họa:
```python
from Crypto.Util.number import *
import gmpy2

e = 17
c1 = 5281902984460481872302011044114495295234706883691270450730514347553367729238298595829480655414548578940224329381972042327440066670142366495280771989420757877500383415087347958655409229805727133604659164018942437897797502973158822281545452793162139435644545907400047562338947483265323747272064512895032117277125123806241924006024065776471160313966595545372454577848929238063734964580623425517430922461778531674407648652147793048655534309061064293141379907098205500027275675907609664817506677507430929046690025280013453016187259205326639860958728201747428903509610925019408056231238340322831006094356755532942788059845
n1 = 16930644133133585153982116446709052721672748348204781862085225308015958369430178426924538163682833765362822077349105004445448958262188377554881412690572248052350840173351221808492539562404392378070802786671280372543130448307383633438827466178723748896312100460675703702162271014860469664170242386651584282586901993638538797099854814661924313225993112751308504309349333978398784283221774291656840002217537988653138155296055099768818584462192204413162324165236392979907684140656757898307337905401896581249560678489854415726470019798795208823138650333827337983608326844617365113983298696064210393115154759291454195692373


c2 = 6162539726286592168394448349690174616346889109160236370611851880156690694712760329744074831228591055634518601693912353931368848316889426845015738676848439972254280732503854103853320110092491469914385988167410727536596346306843876822277027093518743294669965911466013487176645544303209199706511600822221896442247998987128724332167832065101628368630622196780631151950624374003738598234457262104177776394340556855566300326141831504301005520835753870827859262212652975658548934416777300952082762384420499635206417089278284976520806511553990747668508907624111161554742592764211574031473657602849178212391109386523736123225
n2 = 24517830966075068901143081428136123787052462312728921454664505259135368205967208384321697479280273940725987122343582634769573313694977955351008895829262278664950511633319526458471500717719183843537956381037748017055977477231213564700962749046423150919990089564077863308748604142838798184581851355965003040482172222846012964383746163017000648375552920723819402398890728926342009527890326964300454951835432280426955033831895830700954905020816313887830291466080919961631523098068933610444428612902610455365013948374770977767001367985317420877941833498437819340406382755518088589696697321340723109560066075801867816757243

c3 = 19908100167530216645294949759783346545029235701853013289113833267209207614808513713310237969750220599230702392524311814340229834745985200556448477263767965831011135495482388430411710703857335313563121388465470530848661415361605517365926771165709472561083643203337808374724449086723593596845700498749711885216543551227316982638103624172386677548005428618414955857762672903247827644153128066936494858165396265940016365364770664110861333303512475064549820159646008318554658964484061481333613199128577346633337396079262450825350654019895506969392774300773381808489530831368833223045245411050842234360325298418088989859161
n3 = 21404493333459773651833468889494854452146341909489290362795042422081025549394197696207194740465796006865793114554826965350325270688131352372790308281188594067594092027310514703330195829475266538616467239956851153498522500671756355728397676054553313625727693338831805978536697927429324389373252910725919888390839180105695354495463820979707332963584951628592768362598994748878184136661630763266935396207706143788599547556573680129113171095202415059427609744739187238102875459200266914230437205151399301939429262300637643779611482708303062671827115951463353597025183123730487168755528498188468405928192815431774026410657



N=n1*n2*n3
N1=N//n1
N2=N//n2
N3=N//n3

u1 = inverse(N1, n1) 
u2 = inverse(N2, n2)
u3 = inverse(N3, n3)

M = (c1*u1*N1 + c3*u3*N3 + c2*u2*N2) % N
m = gmpy2.iroot(M,e)[0]
print(long_to_bytes(m))
```
## 5.Wiener Attack
- Để giảm thời gian giải mã (hoặc thời gian tạo chữ ký), người ta có thể muốn sử dụng một giá trị nhỏ của d hơn là một d ngẫu nhiên. Do lũy thừa mô-đun cần có thời gian tuyến tính trong log2 d, nên một d nhỏ có thể cải thiện hiệu suất ít nhất là hệ số 10 (đối với mô-đun 1024 bit). Thật không may, một cuộc tấn công thông minh của M. Wiener [19] cho thấy rằng một d nhỏ dẫn đến sự phá vỡ hoàn toàn hệ thống mật mã.
- Đặt N= p*q với q < p < 2q . Đặt ![](https://hackmd.io/_uploads/Sy8w0eb5h.png). Cho trước (N,e) với ed = 1 mod phi(N), Marvin có thể phục hồi d một cách hiệu quả.
- Bằng chứng dựa trên các xấp xỉ sử dụng các phân số liên tục. Vì ed = 1 mod phi(N), nên tồn tại k sao cho ed − kphi(N) = 1. Do đó, ![](https://hackmd.io/_uploads/HyEwtb-5h.png)
- Do đó, k/d là một xấp xỉ của e/phi(N). Mặc dù Marvin không biết phi(N), anh ấy có thể sử dụng N để tính gần đúng nó. Thật vậy, vì phi(N) = N − p − q + 1 và p + q − 1 < 3sqrt(N), nên chúng ta có |N − phi(N)| < 3sqrt(N). Sử dụng N thay cho phi(N), chúng tôi thu được: ![](https://hackmd.io/_uploads/SkDUqWZ92.png)
- Bây giờ, kphi(N) = ed − 1 < ed. Vì e < phi(N), chúng ta thấy rằng k < d < ![](https://hackmd.io/_uploads/HJ52cWbc3.png) . Do đó chúng tôi có được: ![](https://hackmd.io/_uploads/HymC9-Zch.png)
- Đây là một quan hệ xấp xỉ cổ điển. Các số lượng phân số k/d với d < N gần đúng với e/N bị giới hạn bởi log2 N. Thực tế, tất cả các phân số như vậy thu được dưới dạng các phần tử hội tụ của khai triển phân số liên tục của e/N . Tất cả người ta phải làm là tính log N hội tụ của phân số tiếp tục cho e/N. Một trong số này sẽ bằng k/d. Vì ed − kphi(N) = 1, nên ta có gcd(k, d) = 1, và do đó k/d là phân số rút gọn. Đây là một thuật toán thời gian tuyến tính để khôi phục khóa bí mật d.
- Code minh họa:
```python
from Crypto.Util.number import*
import owiener
N = 'b12746657c720a434861e9a4828b3c89a6b8d4a1bd921054e48d47124dbcc9cfcdcc39261c5e93817c167db818081613f57729e0039875c72a5ae1f0bc5ef7c933880c2ad528adbc9b1430003a491e460917b34c4590977df47772fab1ee0ab251f94065ab3004893fe1b2958008848b0124f22c4e75f60ed3889fb62e5ef4dcc247a3d6e23072641e62566cd96ee8114b227b8f498f9a578fc6f687d07acdbb523b6029c5bbeecd5efaf4c4d35304e5e6b5b95db0e89299529eb953f52ca3247d4cd03a15939e7d638b168fd00a1cb5b0cc5c2cc98175c1ad0b959c2ab2f17f917c0ccee8c3fe589b4cb441e817f75e575fc96a4fe7bfea897f57692b050d2b'
E = '9d0637faa46281b533e83cc37e1cf5626bd33f712cc1948622f10ec26f766fb37b9cd6c7a6e4b2c03bce0dd70d5a3a28b6b0c941d8792bc6a870568790ebcd30f40277af59e0fd3141e272c48f8e33592965997c7d93006c27bf3a2b8fb71831dfa939c0ba2c7569dd1b660efc6c8966e674fbe6e051811d92a802c789d895f356ceec9722d5a7b617d21b8aa42dd6a45de721953939a5a81b8dffc9490acd4f60b0c0475883ff7e2ab50b39b2deeedaefefffc52ae2e03f72756d9b4f7b6bd85b1a6764b31312bc375a2298b78b0263d492205d2a5aa7a227abaf41ab4ea8ce0e75728a5177fe90ace36fdc5dba53317bbf90e60a6f2311bb333bf55ba3245f'
C = 'a3bce6e2e677d7855a1a7819eb1879779d1e1eefa21a1a6e205c8b46fdc020a2487fdd07dbae99274204fadda2ba69af73627bdddcb2c403118f507bca03cb0bad7a8cd03f70defc31fa904d71230aab98a10e155bf207da1b1cac1503f48cab3758024cc6e62afe99767e9e4c151b75f60d8f7989c152fdf4ff4b95ceed9a7065f38c68dee4dd0da503650d3246d463f504b36e1d6fafabb35d2390ecf0419b2bb67c4c647fb38511b34eb494d9289c872203fa70f4084d2fa2367a63a8881b74cc38730ad7584328de6a7d92e4ca18098a15119baee91237cea24975bdfc19bdbce7c1559899a88125935584cd37c8dd31f3f2b4517eefae84e7e588344fa5'
n = int(N,16)
e = int(E,16)
c = int(C,16)


d = owiener.attack(e, n)

if d is None:
   print("Failed")
else:
  print('d = ' , d)
#d =  4405001203086303853525638270840706181413309101774712363141310824943602913458674670435988275467396881342752245170076677567586495166847569659096584522419007


print(long_to_bytes(pow(c,d,n)))
```
## 6.Blinding Attack
