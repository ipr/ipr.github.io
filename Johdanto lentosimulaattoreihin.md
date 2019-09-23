# Lentosimulaattorit ja niiden ohjelmointi
Ilkka Prusi 2016


## 1. Yleistä
Tässä pyrin avaamaan lentosimulaatioita ja niiden toteuttamista. Suuri osa alan kirjallisuudesta on englanniksi ja käyttää imperial-yksiköitä SI-yksiköiden sijaan, pyrin selventämään näitä tarpeen mukaan.

Yleisesti kotitietokoneilla simulaattorit ovat reaaliaikaisia ja ”man-in-the-loop” simulaatioita kun taas alan tutkimuksessa voidaan käyttää automatisoituja menetelmiä jonkin testiskenaarion laskentaan. 

Teollisuudessa simulaatioissa voi olla mukana aitoa ”hardwarea” jolloin saadaan parempi todenperäisyys mutta vastaavasit kustannukset voivat olla suuremmat ja mahdollisuudet muokata toteutusta pienemmät kuin puhtaasti ohjelmallisessa ratkaisussa. Jätän nämä kirjoituksen ulkopuolelle, tosin innokkaimmat harrastajat voivat ”simpit” ohjaamoissaan usein käyttää aitoja lentokoneen mittareita, kytkimiä yms.

Simulaatiot voidaan jakaa myös ”study” ja ”survey” simulaatioihin. 

Study-simulaatiot ovat huomattavasti todenperäisempiä (realistisempia) mutta myös huomattavasti työläämpiä ja monimutkaisempia toteuttaa. Perusperiaate study-simulaatioissa on mallintaa pieniä yksityiskohtia myöten miten eri komponentit toimivat, esimerkkinä hydrauliikan toiminta, joka vaikuttaa ohjainpintojen käytökseen eri tilanteissa. Esimerkkinä toteutuksesta Digital Combat Simulator (DCS) A-10C lentokoneen simulaatio.

Survey-simulaatiot pyrkivät vain jäljittelemään suorituskykyä ja ovat pelimäisempiä kuin study-simulaatiot. Esimerkiksi sen sijaan että mallinnettaisiin ilmavirtausta suihkumoottorissa ja sen vaikutuksesta työntötehoon käytetäänkin vain työntötehoa kuvaavaa asteikkoa eri moottoriasetuksilla. 

Myös yksi huomattava ero simulaatioissa on lentokoneen eri järjestelmien toteutustaso. Mittaristo on nykyään usein toimiva jokaisessa simulaatiossa, mutta yksityiskohtaisemmissa simulaatioissa eri kytkimiä voi käyttää interaktiivisesti hiirellä ja laitteiden toiminta on mallinnettu. Esimerkkinä ohjaamon ilmastointi ja paineistus: väärillä asetuksilla kuomu voi huuruuntua haitaten näkyvyyttä, pilotti voi kärsiä happivajeesta (hypoxia), ohjaamon kuomu voi irrota kun ilmanpaine-ero ylittää tietyn rajan ja niin edelleen.

Vauriomallinnus on yksi keskeinen tekijä taistelulentämisen simulaatioissa: kun siivessä on reikiä tai toinen peräsin puuttuu pitää lentomallinnuksen vastata muuttuneeseen tilanteeseen. Siviili-ilmailuun keskittyvissä simulaattoreissa ei normaalisti ole kovin edistynyttä vauriomallinnusta. Taistelusimulaatioissa tulee tekijäksi myös maaston ”line of sight” vaikutus, esimerkiksi maayksiköiden kyky seurata ilma-alusta, sekä lentokoneen tutkan kyky havaita kohde maaston aiheuttamasta kohinasta.

Kehittyneissä lentosimulaatioissa mallinnettaan myös lentokoneen käytös lähellä suorituskyvyn rajoja (”edge of envelope”) ja jopa tämän ylityttyä (stall, vaakakierteet ym.) jotta lentäjä voi pyrkiä korjaamaan ja palauttamaan kontrollin mahdollisuuksien mukaan. 

Lentokoneen ja maan pinnan välinen on huomioitava usein tavoin. Maaefektin vaikutus sekä laskutelineiden ja renkaiden kyvyt laskeutumissa näistä ilmeisimpinä tapauksina.

## 2. Aerodynamiikasta
Aerodynamiikassa on huomioitava useita ilmankehän ominaisuuksia, jotka muuttuvat mm. sääolosuhteiden mukaan.

Lentokoneen nopeus tulee vastaan olennaisena tekijänä lähes jokaisessa aerodynamiikkaa koskevassa laskussa. 
Lentokone itse mittaa nopeutta ilman paine-erossa pitot-putken avulla. (lisää havainnekuva)
Tälläisessä putkessa on reikä sivussa, jolla mittaan ”static” painetta (ambient), ja reikä kärjessä, jolla mitataan dynaamista painetta (lentokoneen liikkeestä aiheutuvaa). Dynaamisen ja ”static” paineen erosta saadaan koneen (IAS = Indicated Air Speed). Todellinen nopeus (TAS = True Air Speed) voidaan laskea, mutta häiriötilanteissa kuten pitot-putken jäätyessä IAS on huomattavan virheellinen. Lentäjän on tiedettävä ja tunnistettava näiden ero sekä osattava toimia oikein häiriötilanteissa kuten kytkettävä pitot-putken lämmitys päälle.

Ilmanpaineen lisäksi on huomioitava ilman lämpötila, kosteus ja tiheys. Ilman viskositeetti riippuu tiheydestä ja lämpötilasta, joka tulee yhdeksi tekijäksi yliäänisissä nopeuksissa lentämisen mallintamiseen (yliäänisestä lennosta lisää myöhemmin).

Siiven muodolle ja lentokoneen eri segmenteille määritellään joko kokeellisesti (tuulitunnelli) tai laskennallisesti (CFD-analyysi) kertoimet nosteelle (lift) ja vastavedolle (drag), nämä yleisesti kuvataan termeillä CL ja CD. Tämä on ehdoton minimi simulaatiolle. Aerodynamiikan oppikirjojen perusteella lentävään kappaleeseen vaikuttaa käytännössä kaksi voimaa: ”pressure distribution” ja ”shear stress distribution”. Aerodynamiikkaan syventyessä näihin määrittelyihin perehtyminen on olennaista mutta simulaation toteuttamisessa riittää käsitellä tiettyjä ”coefficient” kertoimia.

Käytettävät ”coefficient” kertoimet ovat suunnattomia (”dimensionless”), joten niitä on helppo soveltaa osana laskukaavaa. Kertoimet määritellään mm. eri asentokulmilla (”angle of attack”, AOA), α. Yleisesti mitä suurempi asentokulma on sitä enemmän siivellä on nostetta, mutta myös vastavetoa. Useille ohjainpinnoille kertoimet määritellään myös sivukulman ”sideslip” suhteen (beta, β).

Kertoimien määrittäminen kullekin ohjainpinnalle ja siiven muodolle on työlästä menetelmästä riippuen ja se on normaalisti tehtävä useilla kulmilla, olosuhteilla ja kombinaatioilla riippuen mallinnuksen kohteesta. Sekä tuulitunnelissa että CFD-analyysissa on huomioitava ongelmakohtia joka vaatii asiaan perehtymistä oikeiden kertoimien saamiseksi. Usein voidaan käyttää laskennallista periaatetta kokeellisten arvojen sovittamiseksi (lue lisää mm. NACA Variable Density Tunnel (VDT)).

Esimerkkinä ”coefficient” kerrointa voidaan käyttää osana kaavaa, kuten ilmajarrun aiheuttama ilmanvastus:
```
CD * cos(kulma) * dynaaminen ilmanpaine * ilmajarrun pinta-ala
```
.. jossa dynaaminen ilmanpaine on:
```
	VT2 * ilmanpaine * 1/2
```
.. jossa VT on nopeus ja ilmajarrun pinta-ala on tunnettu vakio.

Kun hydraulinen ohjaus ilmajarrulle muuttaa sen asentoa, saadaan riittävän realistinen ilmanvastus myös kun jarru ei ole kokonaan sisällä tai kokonaan ulkona. Vastaavat välivaiheet ja muutokset ilmanvastuksessa ovat olennaisia jotta lentämisen vaste pysyy realistisena ilman yllättäviä tai epärealistisia ”pykäliä” tai hyppäyksiä käytöksessä.

Moderneissa hävittäjissä on ohjattavat pinnat sekä siiven etureunassa (leading edge flap, LEF) ja siiven takareunassa (trailing edge flap, TEF). Jälkimmäiset voivat koneesta riippuen yhdistää laskusiivekkeen ja tyypillisen ohjainsiivekkeen toimintoja eri tavoin (usein lentokoneen ohjelmiston hallittavana). LEF ja TEF tarkoitus on muuttaa siiven virtauksen muotoa, jolloin siipi toimii paremmin korkeilla hyökkäyskulmilla ja vähemmällä sakkauksen riskillä (mm. F-18).

Perävakaimet ovat tyypillisesti käytössä pystykulman (pitch) ohjaukseen, mutta on konetyypistä riippuen ne voivat toimia sekä symmetrisesti että differentiaalisesti, jossa jälkimmäinen on käytössä normaalien siivekkeiden avuksi. Peräsin eli sivuvakain on potkurikoneissa olennainen hallittuun käännökseen jotta nokka pysyy horiston tasolla ja olennainen mm. ristituulessa laskeutumiseen, mutta nopeiden suihkuhävittäjien lennossa vähemmän käytössä. Joissakin koneissa vakaimet eivät ole täysin pystysuorassa koneeseen nähden, jolloin niillä voi olla vaikutuksensa myös nostovoimaan (mm. F-18).

Kuten aiemmin mainittu, eri ohjainpinnoille määritellään niiden vaikutukset eri tilanteissa. Kiertomomentit eri osilta voidaan laskea niiden aiheuttamasta nosteesta ja ilmanvastuksesta, sekä sijainnista ja pinta-alasta koneessa. Käytännön esimerkkinä perävakaimen nostovoima ja ilmanvastus vaikuttavat koneen pystymomenttiin CM, jonka perusteella voidaan laskea vaikutus koneen nokan nousuun eri nopeuksilla kuten lentoonlähdön aikana. Sama periaate pätee eri ohjainpinnoille ja niiden vaikutukseen kiertomomentille eri akseleiden suhteen (pitch, roll, yaw).

Coefficient-kertoimet voidaan periaatteessa määritellä funktioilla Reynoldsin numeron (Re) suhteen:
```
	CL = fL(Re, M∞, α)
	CD = fD(Re, M∞ α)
	CM = fM(Re, M∞, α)
```
.. jossa M∞ on Machin numero ”vapaavirtauksessa” ja  α on asentokulma. Käytönnössä voi olla helpompaa mikäli kertoimet ovat suoraan käytettävissä olevia numeroita.

Machin numero M lasketaan paikallisen virtausnopeuden ja äänennopeuden perusteella:
```
M = u / c
```

Äänen nopeus ilmakehässä riipuu mm. ilman tiheydestä ja lämpötilasta ja on siis muuttuva tekijä eri korkeuksilla. Aerodynamiikan laskennassa käytetäänkin usein dynaamista ilmanpainetta, ”impact pressure” qc tai sen suhdetta ”static” paineeseen (Qc/PS) ilmakehässä. Air data computer (ADC) voi tämän perusteella tehdä päätöksen paljonko siivekkeitä ohjataan esimerkiksi transonic nopeuksissa lennon vakauttamiseen.

Tässä lyhyt listaus erilaisia lentokyvyn tilanteita joita yksinkertaisemmat simulaatiot eivät käsittele lainkaan tai eivät käsittele oikein:
* sakkaus (stall)
* buffeting
* vortex ring state (helikopterit)
* sideslip
* vaakakierre
* G-ylitys

## 3. Fysiikan integraatio
Useimmissa simulaatioissa suoritetaan jossakin vaiheessa fysiikan integraatio, jossa yhdistyvät koneeseen vaikuttavat eri voimat. Näitä ovat mm.:
* työntövoima
* noste
* kineettinen energia, inertia
* vääntömomentit

Lisäksi huomioitavia tekijöitä ovat törmäystarkistelu (collision detection) mm. ohjuksen, maaston, rakennuksen jne. kanssa sekä tästä aiheutuvat seurakset.
Fysikaalisten voimien yhdistäminen lentoon on lähes täysin erilaisien voimavektoreiden momenttien yhdistämistä: kineettinen energia (massa, liikesuunta), työntövoima (suuruus, sijainti), nostovoima, ilmanvastus, laskutelineiden ja maan yhteys ym. 
On myös huomioitava ulkoisten tekijöiden vaikutus kuten sivutuuli laskeutuessa, laskutelineiden jousivoima (etenkin kevyet koneet) jne.

Lentävällä laitteella voi olla samaan aikaan siirtymää jokaisella akselilla (pystynopeus, matkanopeus, sideslip), sekä kiertomomenttia jokaisen akselin suhteen. Tästä johtuen nk. 6DOF (”six degrees of freedom”) simulaatio käyttää vektorilaskentaa, tyypillisesti vektoreiden summaa ja ristituloa.
Moottoreiden työntövoimasta ja sijainnista johtuvat suunnan ja momentin muutokset on myös tällöin yksinkertaista yhdistää liikevoimaa riippumatta siitä, tukeeko moottori voiman vektorointia vai ei. Lisäksi esimerkiksi potkurikoneissa potkurin kiertomomentti on merkittävä tekijä laskeutumisessa ja lentoonlähdössä 
Polttoaineen määrä eri tankeissa vaikuttaa lentokoneen inertiaan ja sen kiertomomenttiin ja siten sen lento-ominaisuuksiin. Tankkien sijainti ja polttoaineen määrä eri tankeissa on yksi huomioitava asia, sekä mahdolliset lisäsäiliöt. Erilaiset ulkoiset kuormat kuten lisäsäiliöt, ohjukset ja pommit aiheuttavat paitsi painoa myös ilmanvastusta, joka pienempitehoisien moottorien kanssa voi aiheuttaa merkittäviä rajoitteita mahdollisen kuorman määrälle.

## 5. Ohjelmisto
### 5.1 Yleistä
Simulaatio-ohjelman toteutuksessa on huomioitava useita tarpeita: vaste-aika (reaaliaikaisuus), laskentakapasiteetti (CPU nopeus) ym.

Simulaatiot ovat CPU:lle verrattain raskaampia kuin pelimäisemmät ohjelmat, jotka taas voivat sivuuttaa vaatimukset todenperäisyydestä ja keskittyä efekteihin ja visuaaliseen ilmeeseen.
CFD-analyysi on liian raskasta suoritettavaksi reaaliaikaisessa ohjelmassa. Siksi on käytettävä erilaisia menetelmiä yhtälöiden yksinkertaistamiseen ja laskemalla tietoja etukäteen.
Aerodynamiikan laskuja myös pyritään minimoimaan ja soveltamaan konekohtaisesti. Täysin yleispätevää aerodynamiikkakoodia käytetään harvoin koska se on:
* a) liian raskasta (suorituskykyvaatimukset)
* b) liian karkeatasoista (ei riittävästi konekohtaisien erojen huomiointia)

Tästä johtuen aerodynamiikan aiheuttamat voimat joudutaan tietyissä määrin ohjelmoimaan jopa konekohtaisesti, vertaa esim. delta-siipisen Miragen ja F-16 hävittäjän aerodynaamisia eroja. Tosin on myös paljon koneita joissa sama runko voidaan soveltaa sellaisenaan kuten toisen maailmansodan hävittäjissä usein.

### 5.2 Ohjelmakoodin menetelmät
Olettaen esimerkki jossa ohjainvaste pienellä liikkellä on vähäisempi ja suurella liikkeellä suurempi, voisi karkean toiminnon tehdä käyttäen arvo-aluetta laskennassa:
```C
if (lateralInput > -0.5 && lateralinput < 0.5)
	rollangle = ...
else
	rollangle = ...
```

Menetelmä on yksinkertainen ja helppo toteuttaa mutta epärealistinen ja voi aiheuttaa havaittavaa ”pykälää” toiminnassa tietyllä alueella.

Toinen menetelmä ylläolevaan olisi käyttää nk. lookup-taulua:
```C
int index = 0;
for (; index < tableSize; index++)
	if ( inputTable[index] == lateralInput) break;
rollangle = rollTable[index];
```

Tässä menetelmässä on huomattavasti enemmän todenperäisyyttä, mutta riippuu taulukoiden tarkkuudesta sekä vaatii normaalisti interpolaation väliinjäävien arvojen löytämiseksi. Tämä vielä huomattavasti monimutkaistuu kun on kyse aerodynamiikasta.

Kolmas menetelmä, joka on tarkin mutta voi olla sekä laskennallisesti vaativin että vaikein kehittää, on käyttää yhtälöjoukkoja arvoille. Esimerkki lineaariyhtälönä yksinkertaisuuden vuoksi:
```C
rollangle = lateralInput * multiplier + offset;
```

Käytännössä tarvittava toiminnallisuus on usein huomattavasti yllämainittua monimutkaisempaa.

### 5.3 Lineaarinen vs. epälineaarinen malli
Yksinkertainen tapa toteuttaa malli olisi käyttää lineaarisia yhtälöitä. Valitettavasti useimmissa tapauksissa tällä ei saada realistista mallinnusta.

Tähän mennessä on puhuttu simulaatiosta yleisellä tasolla. Tietyn lentokoneen ominaisuuksien mallintamiseen tarvitaan kuitenkin enemmän yksityiskohtia simulaatioon joka tarkoittaa epälineaarisen mallinnuksen käyttämistä.

Tämä tarkoittaa lisää yksityiskohtia lentokoneen aerodynaamisista ominaisuuksista.

Perinteisesti lentokoneet on suunniteltu aerodynaamisesti stabiileiksi, eli päästäessä irti ohjauksesta kone hakeutuu stabiiliin lentoon. Näissä nostovoiman keskipiste (center of pressure) on lentokoneen keskiakselilla taaempana lentokoneen painokeskipisteestä (center of gravity). 

Modernit hävittäjät sen sijaan ovat usein aerodynaamisesti epästabiileja, joka tarkoittaa että nostovoiman keskipiste on painokeskipisteen edellä. Kone pyrkisi jatkuvasti nostamaan nokan ylöspäin ilman jatkuvaa ohjausta koneen lentopinnoilla lennon vakauttamiseksi. Näissä lentokoneissa normaalisti ohjausjärjestelmässä on vaikutus (control authority) lentotilaan koneen vakauttamiseksi siivekkeiden käytöllä eri lentotiloissa, jolloin lentäjän työkuorma helpottuu.

Esimerkkitapauksina aerodynaamisesti epästabiileista lentomalleista ovat F-16 ja Su-27 hävittäjät. Lentojärjestelmän (flight control system) toiminnan mallintaminen onkin näissä yksi keskeisistä simulaation kohteista itse aerodynamiikan ohella.

Lentojärjestelmä käyttää normaalisti vähintään ilmanpainemittausta ohjaamaan lentäjän antamasta syötteestä käytännössä tapahtuvaa ohjausta. Aiemmin mainittu control authority määrittää paljonko lentojärjestelmä voi vaikuttaa ohjaukseen suhteessa lentäjän antamaan. Lisäksi lentojärjestelmä voi päätellä mitä eri ohjainpintoja tai niiden yhdistelmää käytetään lentäjän antaman syötteen toteuttamiseen jotta lentokone ei pääse hallinnasta.

Eräissä lentokoneissa ohjausjärjestelmät ovat toteutettu analogielektroniikalla (mm. F-16A), mutta JOVIAL-kielellä ohjelmoituja järjestelmiä tavataan uudemmissa. ”Lentävän koodin” toimintojen selvittäminen on yleensä asteita vaikeampaa kuin päätellä puhtaasti aerodynamiikkaan liittyviä ominaisuuksia, koska koneiden ulkomitat ovat helpommin saatavilla ja tarvittavat kertoimet voidaan näiden perusteella selvittää. Eräissä tapauksissa ohjelmaperiaate on kuitenkin saatavilla lohkokaavioina tai jopa niiden toimintaa kuvaavien kaavojen kanssa.

NASA on tehnyt tutkimuksia erilaisien lentokoneiden kehitysvaiheissa ja tästä johtuen joihinkin koneisiin on saatavilla yksityiskohtaistakin tietoa niiden toiminnasta, mutta usein johonkin modifikaatioon liittyen (mm. YF-16 prototyyppi, F16 XL, F-18 HARV).

### 5.4 Fysiikkaintegraatio
Kuten aiemmin mainitsin fysiikan integraatiossa koneeseen vaikuttavat eri voimat yhdistetään. Fysiikkaintegraatio on usein myös yleispätevin osa simulaatiosta, jota voidaan käyttää sellaisenaan tai pienin muutoksin muissakin simulaatioissa.

Usein ohjelmakoodissa on määritelty 3-akselin vektori, jossa on eriteltynä x,y,z akselien suhteen vaikuttava voima. 

Mikäli lasketaan siipeen kohdistuva paine seuraavasti:
```
siipipaine = dynaaminen paine * siipipinta-ala
```
.. siipien nostovoima pystyakselin suhteen:
```C
vec3 lift(0.0, 0.0, siipipaine * Cy_total)
```
.. voidaan nostovoiman vektori lisätä koneeseen vaikuttaviin kokonaisvoimiin:
```C
	common_force.x = lift.x; common_force.y = lift.y; common_force.z = lift.z;
```

Voiman sijaintivaikutus suhteessa painokeskipisteeseen:
```C
	vec3 delta_pos(force_pos.x – cog.x, force_pos.y – cog.y, force_pos.z – cog.z)
```
.. saadaan voiman momentti vektorien ristitulona.

Tällä periaatteella samaan fysiikkaan voidaan lisätä useita vaikuttavia elementtejä ja huomioida sekä niin suuruus että suuntaus. Pommikoneissa kuten B-17 neljällä moottorilla jokaisella on vaikutus sekä koneen suuntaan että kiertomomentti koneen pystyakselin ympäri etäisyyden mukaan.  Näin moottorien eri käyttöteho voidaan myös huomioida lentotilanteen aikana.

## 6. Helikopterilento, VTOL vs. STOL
Helikopterien ts. ”pyöriväsiipisien koneiden” lento on yksi suhteellisen vaativa simuloitava, jossa ilmavirtauksilla on keskeinen osa.

Yleinen vitsi on että helikopterit pysyvät ilmassa koska ovat niin rumia että maa hylkii niitä.
Normaalisti helikoptereissa käytetään yhtä tai kahta suihkumoottoria voimanlähteenä. Suihkumoottorin voima välitetään vakionopeusvaihteistolla pääroottoriin ja peräroottoriin ja lennon aikana moottorin on tavallisesti samalla tehoasetuksella jatkuvasti. Lisätehoa on varattu poikkeuksellisien tilanteiden hallintaan kuten vortex ring state, jossa kopteri menettää nostovoimaansa johtuen ilman virtauksesta alaspäin roottorin ajautuessa itsensä aiheuttamaan virtaukseen.

Helikopterin roottorin pyöriessä lavat tuottavat ilman alaspäin virtauksen, joka toimii koneen nosteena. Tavallisimmissa helikoptereissa roottorin vääntömomenttia kompensoidaan peräroottorilla (mm. UH-1).  On olemassa myös koptereita, joissa peräroottorin sijaan käytetään kahta roottoria (mm. CH-47, Ka-50, Ka-52). Asian yksinkertaistamiseksi puhutaan tavallisesti yleisemmästä konfiguraatiosta yhdellä pääroottorilla ja yhdellä peräroottorilla. 

Roottorin tuottaman virtauksen ohjaaminen eri kulmassa tuottaa liikeen eteen/taaksepäin tai sivuille, jolloin kopteria kallistetaan menosuuntaan kohti. Seurauksena nostovoimasta osa on ”työntövoimaa”, jolloin nostovoima vähenee mutta tätä voidaan kompensoida roottorin lapakulmaa muuttamalla. Tämän seurauksena taas roottoriin kohdistuvat suuremmat vääntövoimat jota kompensoidaan lisäämällä peräroottorin lapakulmaa.
Helikopterissa siis ei ole koskaan erillistä lentomallia nousuun tai matkaan kuten joskus näkee väitettävän. Kyseessä on ainoastaan tiettyjen voimien suuruudesta ja suuntauksesta.
VTOL lentokoneissa (mm. Harrier) ei ole myöskään erilaista lentomallia ”matkalentoon” vaan kyse on vain työntövoiman suuntaamisesta: Harrier käyttää sivuilla olevia suuttimia moottorin tuottaman työntövoiman suuntaamiseen jolloin saadaan leijunnan ja matkalennon välillä useita eri nopeuksia.
Lentokoneissa, joissa on työntövoiman vektorointi (mm. F-22), löytyvät jälleen samat periaatteet: työntövoiman suuntaus tekee antaa tietyn kiertomomentin koneen lennolle suunnan, sijainnin ja voiman mukaan. Monimoottorisissa koneissa (mm. B-17) on myös sama ilmiö kun moottorit toimivat eri asetuksilla tai kun osa on sammutettuina.

## 7. Yliääniset nopeudet
Aliäänisillä nopeuksilla (mach numero <1) ilmakehää voidaan mallintaa pääosin ”kiinteänä” elementtinä. Yliäänisillä nopeuksilla (mach numero >1) on huomioitava ilman virtaukset suuremmalla tarkkuudella josta tulee huomattavasti lisää työtä.

Yliäänisillä nopeuksilla on mm. arvioitava shokkiaallon muodostuminen siiven pinnalla ja sen vaikutus ohjainpinnan toimintakykyyn. Aallon kohta voi aiheuttaa sen, että varsinainen ohjainpinta on alemman paineen alla eikä sen vaikutus lentokoneen ohjattavuuteen tai vakauteen ole vastaavanlainen kuin aliäänisissä nopeuksissa.

Yliäänisillä nopeuksilla lentokoneen pinnan ja ilman välinen kitka nousee merkittäväksi tekijäksi laskettaessa koneen nopeus tietyissä olosuhteissa tietyllä työntöteholla. Tässä huomioidaan siiven pinnassa ja tietyllä etäisyydellä olevan ilman rajakerros (boundary layer) ja siinä tapahtuva virtausnopeuksien välinen ero.

Asentokulmaa nostaessa ”laminar flow” virtaus muuttuu ”turbulent flow” virtaukseen jolla on suurempi ilmanvastus ja siten vaikuttaa koneen nopeuteen enemmän.

Suurilla yliäänisillä nopeuksilla ilman kitkan aiheuttama lämpötila voi nousta merkittäväksi tekijäksi. ”Hypersonic” (mach numero > 5) nopeuksissa ongelmat suurenevat huomattavasti.

Tässä vain muutamia huomioita yliäänisissä nopeuksissa tapahtuvan lennon simulointiin. Aihe on melko monimutkainen ja siitä pitäisi kirjoittaa huomattavan paljon.

## 8. Järjestelmämallinnus
Lentokonejärjestelmien kuten avioniikan simulointi ja mallintaminen ovat oma kokonaisuutensa.
Avioniikaan kuuluu perusmittareita (korkeus, suunta ja navigaatio, ADI, HSI) sekä monimutkaisempia kuten aseiden hallintajärjestelmät, tutkat, ohjelmoitavat omasuojalaitteet ym.

Esimerkkinä korkeusmittari kertoo korkeuden pitot-putken antaman tiedon perusteella, joka perustuu ilmanpaineeseen. Dynaaminen ilmanpaine pitot-putkessa riippuu korkeuden lisäksi lentonopeudesta, jolloin todellinen korkeutta kertova arvo on dynaamisen ja staattisen ilmanpaineen välinen ero. Lisäksi putken jäätyminen ja jäätymistä poistava lämmitys vaikuttavat annettuun arvoon.

Lentokonejärjestelmien mallintamiseen ei ole mitään yhtä yleispätevää lähestymistapaa, mutta tiettyjä komponentteja voi käyttää sellaisenaan useissa konetyypeissä jotka käyttävät vaikkapa samaa mittarityyppiä.

## 9. Yhteenveto
Toivottavasti tämän lukiessa jollakin herää kiinnostus perehtyä aiheeseen enemmän. Tavoitteena oli hieman avata simulaatioiden toteutuksia. Aiheesta voisi kirjoittaa huomattavan paljon enemmänkin.

## Materiaalia
Materiaalia kiinnostuneille:
* https://github.com/ipr/F-16Demo/
* http://www.virtualpilots.fi/feature/articles/109myths/

## Viitteitä
Kirjallisuutta aiheesta kiinnostuneille:
* Fundamentals of Aerodynamics, John D Anderson Jr.
* An introduction to computational fluid dynamics – The finite volume method, Versteeg & Malalasekera

Kehittyneitä simulaattoreita kotikäyttöön:
* [DCS World]: https://www.digitalcombatsimulator.com
* [X-Plane]: http://www.x-plane.com
* [IL-2 Sturmovik]: http://il2sturmovik.com
* [Falcon BMS]: https://www.bmsforum.org/forum/

Avoimen lähdekoodin projekteja (vaihteleva laatu):
* FlightGear
* JBSim
* FreeFalcon

CFD-ohjelmia:
* [OpenFOAM]: http://openfoam.org

Muuta ohjelmistoa:
* [JOVIAL]: https://en.wikipedia.org/wiki/JOVIAL

