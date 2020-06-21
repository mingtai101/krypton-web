//var CryptoJS=CryptoJS||function(e,z){var m={},y=m.lib={},i=function(){},d=y.Base={extend:function(f){i.prototype=this;var g=new i;f&&g.mixIn(f);g.hasOwnProperty("init")||(g.init=function(){g.$super.init.apply(this,arguments)});g.init.prototype=g;g.$super=this;return g},create:function(){var f=this.extend();f.init.apply(f,arguments);return f},init:function(){},mixIn:function(f){for(var g in f){f.hasOwnProperty(g)&&(this[g]=f[g])}f.hasOwnProperty("toString")&&(this.toString=f.toString)},clone:function(){return this.init.prototype.extend(this)}},a=y.WordArray=d.extend({init:function(f,g){f=this.words=f||[];this.sigBytes=g!=z?g:4*f.length},toString:function(f){return(f||r).stringify(this)},concat:function(g){var k=this.words,j=g.words,f=this.sigBytes;g=g.sigBytes;this.clamp();if(f%4){for(var h=0;h<g;h++){k[f+h>>>2]|=(j[h>>>2]>>>24-8*(h%4)&255)<<24-8*((f+h)%4)}}else{if(65535<j.length){for(h=0;h<g;h+=4){k[f+h>>>2]=j[h>>>2]}}else{k.push.apply(k,j)}}this.sigBytes+=g;return this},clamp:function(){var f=this.words,g=this.sigBytes;f[g>>>2]&=4294967295<<32-8*(g%4);f.length=e.ceil(g/4)},clone:function(){var f=d.clone.call(this);f.words=this.words.slice(0);return f},random:function(f){for(var h=[],g=0;g<f;g+=4){h.push(4294967296*e.random()|0)}return new a.init(h,f)}}),p=m.enc={},r=p.Hex={stringify:function(g){var k=g.words;g=g.sigBytes;for(var j=[],f=0;f<g;f++){var h=k[f>>>2]>>>24-8*(f%4)&255;j.push((h>>>4).toString(16));j.push((h&15).toString(16))}return j.join("")},parse:function(g){for(var j=g.length,h=[],f=0;f<j;f+=2){h[f>>>3]|=parseInt(g.substr(f,2),16)<<24-4*(f%8)}return new a.init(h,j/2)}},c=p.Latin1={stringify:function(g){var j=g.words;g=g.sigBytes;for(var h=[],f=0;f<g;f++){h.push(String.fromCharCode(j[f>>>2]>>>24-8*(f%4)&255))}return h.join("")},parse:function(g){for(var j=g.length,h=[],f=0;f<j;f++){h[f>>>2]|=(g.charCodeAt(f)&255)<<24-8*(f%4)}return new a.init(h,j)}},b=p.Utf8={stringify:function(f){try{return decodeURIComponent(escape(c.stringify(f)))}catch(g){throw Error("Malformed UTF-8 data")}},parse:function(f){return c.parse(unescape(encodeURIComponent(f)))}},n=y.BufferedBlockAlgorithm=d.extend({reset:function(){this._data=new a.init;this._nDataBytes=0},_append:function(f){"string"==typeof f&&(f=b.parse(f));this._data.concat(f);this._nDataBytes+=f.sigBytes},_process:function(j){var s=this._data,q=s.words,h=s.sigBytes,l=this.blockSize,k=h/(4*l),k=j?e.ceil(k):e.max((k|0)-this._minBufferSize,0);j=k*l;h=e.min(4*j,h);if(j){for(var g=0;g<j;g+=l){this._doProcessBlock(q,g)}g=q.splice(0,j);s.sigBytes-=h}return new a.init(g,h)},clone:function(){var f=d.clone.call(this);f._data=this._data.clone();return f},_minBufferSize:0});y.Hasher=n.extend({cfg:d.extend(),init:function(f){this.cfg=this.cfg.extend(f);this.reset()},reset:function(){n.reset.call(this);this._doReset()},update:function(f){this._append(f);this._process();return this},finalize:function(f){f&&this._append(f);return this._doFinalize()},blockSize:16,_createHelper:function(f){return function(h,g){return(new f.init(g)).finalize(h)}},_createHmacHelper:function(f){return function(h,g){return(new o.HMAC.init(f,g)).finalize(h)}}});var o=m.algo={};return m}(Math);(function(i){for(var B=CryptoJS,n=B.lib,A=n.WordArray,m=n.Hasher,n=B.algo,e=[],b=[],y=function(f){return 4294967296*(f-(f|0))|0},z=2,d=0;64>d;){var c;o:{c=z;for(var p=i.sqrt(c),r=2;r<=p;r++){if(!(c%r)){c=!1;break o}}c=!0}c&&(8>d&&(e[d]=y(i.pow(z,0.5))),b[d]=y(i.pow(z,1/3)),d++);z++}var o=[],n=n.SHA256=m.extend({_doReset:function(){this._hash=new A.init(e.slice(0))},_doProcessBlock:function(G,F){for(var H=this._hash.words,E=H[0],D=H[1],t=H[2],x=H[3],q=H[4],w=H[5],v=H[6],u=H[7],s=0;64>s;s++){if(16>s){o[s]=G[F+s]|0}else{var a=o[s-15],C=o[s-2];o[s]=((a<<25|a>>>7)^(a<<14|a>>>18)^a>>>3)+o[s-7]+((C<<15|C>>>17)^(C<<13|C>>>19)^C>>>10)+o[s-16]}a=u+((q<<26|q>>>6)^(q<<21|q>>>11)^(q<<7|q>>>25))+(q&w^~q&v)+b[s]+o[s];C=((E<<30|E>>>2)^(E<<19|E>>>13)^(E<<10|E>>>22))+(E&D^E&t^D&t);u=v;v=w;w=q;q=x+a|0;x=t;t=D;D=E;E=a+C|0}H[0]=H[0]+E|0;H[1]=H[1]+D|0;H[2]=H[2]+t|0;H[3]=H[3]+x|0;H[4]=H[4]+q|0;H[5]=H[5]+w|0;H[6]=H[6]+v|0;H[7]=H[7]+u|0},_doFinalize:function(){var g=this._data,j=g.words,f=8*this._nDataBytes,h=8*g.sigBytes;j[h>>>5]|=128<<24-h%32;j[(h+64>>>9<<4)+14]=i.floor(f/4294967296);j[(h+64>>>9<<4)+15]=f;g.sigBytes=4*j.length;this._process();return this._hash},clone:function(){var f=m.clone.call(this);f._hash=this._hash.clone();return f}});B.SHA256=m._createHelper(n);B.HmacSHA256=m._createHmacHelper(n)})(Math);
var SRP6CryptoParams={N_base10:"21766174458617435773191008891802753781907668374255538511144643224689886235383840957210909013086056401571399717235807266581649606472148410291413364152197364477180887395655483738115072677402235101762521901569820740293149529620419333266262073471054548368736039519702486226506248861060256971802984953561121442680157668000761429988222457090413873973970171927093992114751765168063614761119615476233422096442783117971236371647333871414335895773474667308967050807005509320424799678417036867928316761272274230314067548291133582479583061439577559347101961771406173684378522703483495337037655006751328447510550299250924469288819",g_base10:"2",k_base16:"5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300"};
function SRP6JavascriptClientSessionSHA256(){}SRP6JavascriptClientSessionSHA256.prototype=new SRP6JavascriptClientSession();SRP6JavascriptClientSessionSHA256.prototype.N=function(){return new BigInteger(SRP6CryptoParams.N_base10,10)};SRP6JavascriptClientSessionSHA256.prototype.g=function(){return new BigInteger(SRP6CryptoParams.g_base10,10)};SRP6JavascriptClientSessionSHA256.prototype.H=function(a){return CryptoJS.SHA256(a).toString().toLowerCase()};SRP6JavascriptClientSessionSHA256.prototype.k=new BigInteger(SRP6CryptoParams.k_base16,16);
