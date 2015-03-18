#JavaCard Crypto Example

This is the SRC folder of many project about JavaCard.
Main goal is to give some example of security implementation.

##Folder Organization :

.HelloCrypt <br>
:: Basic JavaCard application with basic crypt protocol.
> Terminal ask for a session Token  
> Card generate a DES key and answer with a crypted + signed msg.  
> Terminal decrypt and use the DES Key to crypt all communication  
> All msg have a MAGIC byte.If one message don't have it, it stop communication.  


##File Description :

.\README : this file  
.\AUTORS : list of authors  
.\INSTALL : how to install and compile projects  
.\LICENSE : license file for the project  
.\CONTRIBUTING : How To contribute  

##License :

Under the MIT License (MIT)
