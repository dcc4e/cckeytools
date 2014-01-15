'''
@author: dcc4e
Distributed under the MIT software license, see the accompanying
file LICENSE or http://www.opensource.org/licenses/mit-license.php.
'''

import unittest
import cckeygen

class Test_cckeygen(unittest.TestCase):
    def _test_cckeygen(self, settings, salt, password, expected):
        genOut = cckeygen.generateOutput(settings, password, salt, 0, 1, False)
        if settings.outType == 'electrum' or settings.outType == 'bytes' or settings.outType == 'hex':
            self.assertEqual(expected, genOut[1])
        else:
            self.assertEqual(expected, (genOut[1], genOut[3]))
                    
    def test_cckeygen(self):
        print 'cckeygen test'
        class Settings(): pass
        settings = Settings()
        settings.verbose = False
        settings.doubleCheck = False
        settings.outType = 'address'
        settings.isTestnet = False
            
        #SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS
        #PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
        
        #SHA-1
        settings.hashFunction = cckeygen.keyDerivationFunctions['pbkdf2-hmac-sha-1'][1]
        settings.iterations = 1
        self._test_cckeygen(settings, '', '', ('1e437a1c79d75be61e91141dae20affc4892cc99abcc3fe753887bccc8920176', '1KX19bUFcHEBxAR4BTZX4JXzuUUcLEXPKS'))
        self._test_cckeygen(settings, '', 'passphrase', ('aa76522175a331d217ccbf0689ca1c9f38cd1c9200285dc6066beaace4e9a187', '1KuZkNXLRJmq6vnitgXqM1y4kqrjxkQvwy'))
        self._test_cckeygen(settings, 'salt', 'passphrase', ('7f7042f41820d039e1163bdaa58c671df1e4eb559e4b2d114daf254858399cf3', '1Q4k1fSTRtUmRV5kjrYBCDRcsxGwimmuht'))
        self._test_cckeygen(settings, 'S', 'P', ('0f3d2c14e7e5e6edb988e8aaf9e7604f4cea8f934c8359dac60e3dbaf00d5d7d', '1Kxx9xj5igV3t5ncKGWrUdpnF4vZBa1Ytx'))                
        self._test_cckeygen(settings, 'S'*64, 'P'*64, ('3c12e3fbf11a93b7820cda63be713ab3cb0bd73effd468db2e963248c8d9effa', '18wurjAPQatzNAdSHU4d68p3Drj2dnChWN'))
        self._test_cckeygen(settings, 'S'*64, 'P'*65, ('b88c7776664f50801eed2933f48778e037824e509f125b2bf195a6fedd36d1c4', '1J7nmczJoHmKMqRffWrNvkLr2YULarEKi1'))
        self._test_cckeygen(settings, 'S'*65, 'P'*65, ('f1663dcf7752641973bbb1f6a4f4ecf2e4b1823199a77c456a51fbdb8f79957b', '1AQjri1QXh2QwhXuLTW8PuKvcZyeLsRc5A'))
        settings.iterations = 1024
        self._test_cckeygen(settings, 'salt', 'passphrase', ('d8f426573d87806d51b45af03ea7cfb602053c837b3d87af8fa8a55084585036', '17kLDdZjWexMRvLMDKBZWJejZ8icaEHe4s'))
        settings.iterations = 4096
        self._test_cckeygen(settings, 'salt', 'passphrase', ('46f64f93a148e23d603aa6df7c89f24fb71d9fc74f5a0ca82a321f05605ccbfc', '1Ey2iXoMxjd4dFmrjqGYtemBDKKMaqhUhQ'))
        settings.iterations = 2**20
        self._test_cckeygen(settings, 'salt', 'passphrase', ('1e6474319461e292f83c765fff3557aa19cf8feb5f0d59600b098de971afcedf', '1CjWfe296HqLAhCUt7YEHjk7hbVupcUEfs'))
        settings.iterations = 1
        settings.outType = 'electrum'
        self._test_cckeygen(settings, 'salt', 'passphrase', '7f7042f41820d039e1163bdaa58c671d')
        settings.outType = 'armory'
        self._test_cckeygen(settings, '', '', ('sogf krsu keik htoj soes sgsi roda rnnu kdjj gwed uuee rtuu fnok hfww ktuu uwed askj tnnt', 
                                               'wajw otni tawh geaa sgte dueo ttdj kren tujh duwd usne dsje ttuf wowo ffjt jfur tank jisi'))
        self._test_cckeygen(settings, 'salt', 'passphrase', ('knka gdng swda iafe ossj ftir rhwu jksi tedo nsog othh eogt diss girn dhgw hwfe eunf wrno', 
                                                             'ijdn diig aids jhej etse eajn rerg ruuo ndie nhnw rtdn kkwa tthr twff sdra iadr khse turk'))
        self._test_cckeygen(settings, 'S'*65, 'P'*65, ('nsjj fiun kkhd jgse kftt tsnj rgng ound ffuu ogts wdfs eerk kugh jrhs ntit wnke ehkt hggn', 
                                                       'nees grir atda nuae ehgw erjk hins huie ojej rwaj owsh heos owiu siwu eokg gfid wjju reog'))
        settings.iterations = 1024
        self._test_cckeygen(settings, 'S'*65, 'P'*65, ('gdwd otgg hwut fsio onsn oojk wfja nddi wogd sduu wkau waro erhi ktof djwd sens deuk treu', 
                                                       'nfrf jsof aujj haot njfd weuu naun dsfr atrk hrwg oned fkfj edre tnie shsj gkoj fswu untd'))
        settings.iterations = 4096
        self._test_cckeygen(settings, 'S'*65, 'P'*65, ('twgg kake orhw uohu kwnj twau rink ohei sffk daah jtsd aehg jwua hfhg wjak jfrg nrwf fkit', 
                                                       'newr fheh noas ieer jkat wdja hrfd kjef ufka nsss rhad adnd fkgf ooiu igad tndj iikd dhda'))
        settings.outType = 'address'
                
        #SHA-256
        settings.hashFunction = cckeygen.keyDerivationFunctions['pbkdf2-hmac-sha-256'][1]
        settings.iterations = 1
        self._test_cckeygen(settings, '', '', ('f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad', '18WB96h5RgZMJ3beZw1PEZgosHiPetEgs5'))
        self._test_cckeygen(settings, '', 'passphrase', ('6e2451337ecf2ac7aa7fd043419bb6e3b7ae80ce0f0469a01d1ca56da50d1612', '1BBpGnmrxvUgRvMnEXJGZGDuQ6f4W2Pyvf'))
        self._test_cckeygen(settings, 'salt', 'passphrase', ('2ef9aabdeca6241881d1898162a15a37a4d68715ba97c42eb21fd739b5df713e', '19sFChjbqCdhakDyeKeoRpBzEVC3FZzXK1'))
        self._test_cckeygen(settings, 'S', 'P', ('009827b7f80e38a59726c6a978a9390837314510974435d0c3fc94e0efbffbec', '15AkSniMnz9j22QfHohMkdHkU1GMRyuBno'))        
        self._test_cckeygen(settings, 'S'*64, 'P'*64, ('117767b4bc288bc76c6d305dcadbf6abc7a64de025dcc34c2c8ea2a587552b46', '1Dm9waG6KxwhTfZeR7FnkVH6N6XMRVkVDF'))
        self._test_cckeygen(settings, 'S'*64, 'P'*65, ('49415a41be41fc86e9fe64380dd20289274294e6d75a67ae8cbe5c55c015b84b', '1DgYZXbfQtNMQEW6hm42Egcr1a5jq6nxmf'))
        self._test_cckeygen(settings, 'S'*65, 'P'*65, ('239203745d14f35534916d1a0ef280cee4f79a80b9779c1149b87f6399484397', '19wD9Y7nZa4WVKwAmT9HXiHYZ33e8vxRnM'))
        settings.iterations = 1024
        self._test_cckeygen(settings, 'salt', 'passphrase', ('33ed9f151f86f2820e9a21eae248f5b8d9e0b1b828fef4de024aa3e85ffcb652', '1JMpBgVYcsCSCZ8z2CbfziNrYVhcLMwx2i'))
        settings.iterations = 4096
        self._test_cckeygen(settings, 'salt', 'passphrase', ('29ed930e2ba1c5fb16002ce6cee63e518e02365522eb9f3e377a6d7d6cc16e5b', '1EnbBMpvB3dseYBNhQ4NUUc4TKQVz9SZt'))
        settings.iterations = 2**20
        self._test_cckeygen(settings, 'salt', 'passphrase', ('df03b6eda12adfbd42a938871e3a443dd0bfd7d6f07fb736a83032359163e3c6', '18woQ1HLTDVLGJcDsoes8APps9PaFpCjZq'))
        settings.iterations = 1
        settings.outType = 'electrum'
        self._test_cckeygen(settings, 'salt', 'passphrase', '2ef9aabdeca6241881d1898162a15a37')
        settings.outType = 'armory'
        self._test_cckeygen(settings, '', '', ('nkuo atjh fidi kdrg sawu nhrt oesd nnii nfnf kkkj sjit ttdk rkao wdag nfro dian jnri jdur', 
                                               'wenj wngw ssis owkt uuft ikga aren nide khuo aegn aswg jfeh kgnf eroh rsfs hdsk tuik dwgf'))
        self._test_cckeygen(settings, 'salt', 'passphrase', ('done rrti ourj dgsw wsis wews jdrs hrfk riid rgij wksh trek ugdo tdsn ikfe thin ksfo ttke', 
                                                             'gkfi urda kajj dtgr ijai ooif uwof wnfh trta ddwa tiui nnfd utso twie uhsf nksn urns ktsu'))
        self._test_cckeygen(settings, 'S'*65, 'P'*65, ('dfed afkg hisg nfhh fges jisr aond wauo sent ognk erwa tekk euss getw knjf eegw gfek onkf', 
                                                       'trwi wghg jkuo tfsi grjr dwsf kuig hnss uwho whjj tgfh gtih nkht fsrw duje eduj tagd fhno'))
        settings.iterations = 1024
        self._test_cckeygen(settings, 'S'*65, 'P'*65, ('rjfh fant ddtk jesn jnhw saga jknr fkfi htne soaw wdin tssg aatr jiht gguf khsk uuko jngh', 
                                                       'aiih orer gseg rdki suks rjjt oawd wins dujr eafd ikfe tnes ouwe hdat gwut ktet osfn ihro'))
        settings.iterations = 4096
        self._test_cckeygen(settings, 'S'*65, 'P'*65, ('gnkg hfig dekd oifi jsuo dfhw ooho rtwt rawf kgeh okji ueef were naja noit ruek dnjj idhr', 
                                                       'kaue nuwd fwwn hejj okeg ftde ruei tfao kitw doia ejow rjfo ajhw edgf dwow fjge jwii oeik'))
        settings.outType = 'address'
                
        #SHA-512
        settings.hashFunction = cckeygen.keyDerivationFunctions['pbkdf2-hmac-sha-512'][1]
        settings.iterations = 1
        self._test_cckeygen(settings, '', '', ('6d2ecbbbfb2e6dcd7056faf9af6aa06eae594391db983279a6bf27e0eb228614', '12xGf1BCp5NjTDWSwuk6qnpxEHyrJePCMS'))
        self._test_cckeygen(settings, '', 'passphrase', ('66b9a29aae7cfeaf5950deed2d636a4eb1979fdd87d89b2664a1f625fb4bbd41', '1CVaB2TJHCnmejyXYfphZKLvdLzhJjt359'))
        self._test_cckeygen(settings, 'salt', 'passphrase', ('58700dce6cf6c584936cf5d2ca746d8f4b8a8ccf620f06e2bcc475d4a091e8d4', '19LbZUBEeJqezLtZJB8NzBgCL5bv2HppSx'))
        self._test_cckeygen(settings, 'S', 'P', ('61f7443657de8bf6482bfb009b33db08cbce7ca3c1a3073f880f7b11c2264bdf', '1L3QS8yvr5ojPPyDCiqoi3spYM22ZDoXp1'))
        self._test_cckeygen(settings, 'S'*128, 'P'*128, ('b8ae2ecb9f3e2f57de979c7dad32b017c9963b24ed1df1754f5f3a1b849ca64e', '1Eqy98f4R1TV1gPSDmCsW2XzsybCJCXtrW'))
        self._test_cckeygen(settings, 'S'*128, 'P'*129, ('2baae993beaec99b5964e29f6132cd6915f8c05122183803f6e26e52b09bbde9', '13kUzTwGTVTCitCy54e63xW5X15xQJZuJt'))
        self._test_cckeygen(settings, 'S'*129, 'P'*129, ('8384753ebe57412d785f9a596e76a8522fe67daad545a94fee61e6571dfd5ec3', '1K1BVPa79ak4GJk1tzepxHHU1HpkeuKQEx'))
        settings.iterations = 1024
        self._test_cckeygen(settings, 'salt', 'passphrase', ('b6274f0cc0a31676e831bcebe0924861dd27b9e6a0df0e306f127a1f3fdb1cdd', '1MqfxdoDgqkJun2DfoZNta3ma3SvBrmoys'))
        settings.iterations = 4096
        self._test_cckeygen(settings, 'salt', 'passphrase', ('f4a816a55b67a75ceab6912680bad34599287cfb6cfdfce5a954ed68a7c8d14a', '1KeHGzTPDbHkAmbdRw9XZvZhnDEtNoTZ4E'))
        settings.iterations = 2**20
        self._test_cckeygen(settings, 'salt', 'passphrase', ('53448831716b0c052a508e6455f258bcd80d191b0f4db5322b0b23ef37cf630e', '1by648JiY9sGDbAwBzHgFSXP9ya2psK61'))
        settings.iterations = 1
        settings.bytes = 32
        settings.outType = 'bytes'
        self._test_cckeygen(settings, '', '', '6d2ecbbbfb2e6dcd7056faf9af6aa06eae594391db983279a6bf27e0eb228614')
        settings.outType = 'hex'
        self._test_cckeygen(settings, 'salt', 'passphrase', '58700dce6cf6c584936cf5d2ca746d8f4b8a8ccf620f06e2bcc475d4a091e8d4')
        settings.outType = 'electrum'
        self._test_cckeygen(settings, 'salt', 'passphrase', '58700dce6cf6c584936cf5d2ca746d8f')
        settings.outType = 'armory'
        self._test_cckeygen(settings, '', '', ('jido uttt ntdo jiui kahj nrne rnjr rajo uouj rohe gfes itew fdke rjtn dkoa otdd wjsg sjut', 
                                               'frta ueej nffu rgtj jkoe ghwd eorj effg foiw andw fske kfdg ohnf sins wois ksis wuek gikh'))
        self._test_cckeygen(settings, 'salt', 'passphrase', ('hwka aiuo junj uhwg efju nhid urkg jiwn snus gtwr wuun jdan ajod tuug khig raes owig fodi', 
                                                             'nnss gadg onkj shar srjd snhe rkea dswk kotf jieh erds rsun fkkt ufki naeu ohrw tnwk toud'))
        self._test_cckeygen(settings, 'S'*129, 'P'*129, ('wfwg khfo tohk gsdi kwhn erhe jokj rwhd gnie dnoj kirr ihgh regn oojs ojhk sini houf kkna', 
                                                         'jwah eesu ahor iwur asrj kduh htne otss efio ednh fegj ssdj teer ijgt kdks uggw aiwi euta'))
        settings.iterations = 1024
        self._test_cckeygen(settings, 'S'*129, 'P'*129, ('huhn srwt afis etud ader todd iais gjsk dhwf jdsh nffk ufwu afin fwhe efgs nwkt ants sdrd', 
                                                         'rgtf oohe ikre krge ekdu enwa rrou sdok daud isfo ngdg ntsf finu tfwh tsda tfrf kssr ewsu'))
        settings.iterations = 4096
        self._test_cckeygen(settings, 'S'*129, 'P'*129, ('jktj haef fhao tuga hofk ehsd kfwt finn uhif hiku gajn dhfd jskw wegh nwdf dfrn ogfg gthf', 
                                                       'esjj inuw gwoe tahu ggtj frhs ejod thrt dofw riee eius egui ahhd owku koia rogo rkfa atsn'))
        settings.outType = 'address'
        
        settings.isTestnet = True
        self._test_cckeygen(settings, 'salt', 'passphrase', ('f4a816a55b67a75ceab6912680bad34599287cfb6cfdfce5a954ed68a7c8d14a',
                                                             'mzAEa3YN2cizwt5F9W7uPqn2eCqbK5K7nW'))
                
        
        

if __name__ == "__main__":
    unittest.main()