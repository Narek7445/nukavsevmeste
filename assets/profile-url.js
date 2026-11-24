(function(){
  const map={а:"a",б:"b",в:"v",г:"g",д:"d",е:"e",ё:"e",ж:"zh",з:"z",и:"i",й:"y",к:"k",л:"l",м:"m",н:"n",о:"o",п:"p",р:"r",с:"s",т:"t",у:"u",ф:"f",х:"h",ц:"ts",ч:"ch",ш:"sh",щ:"sch",ъ:"",ы:"y",ь:"",э:"e",ю:"yu",я:"ya"};
  window.contestantProfilePath=function(value){
    const slug=String(value||"").toLocaleLowerCase("ru").replace(/[а-яё]/g,ch=>map[ch]||ch).replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"").slice(0,150)||"item";
    return "/contestants/"+slug+"/";
  };
})();
