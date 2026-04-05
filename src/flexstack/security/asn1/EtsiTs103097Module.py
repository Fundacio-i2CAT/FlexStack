# pylint: skip-file
ETSI_TS_103_097_MODULE_ASN1_DESCRIPTIONS = """
EtsiTs103097Module
{itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) secHeaders(103097) core(1) major-version-3(3) minor-version-2(2)} 

DEFINITIONS AUTOMATIC TAGS ::= BEGIN

IMPORTS

Ieee1609Dot2Data, Certificate
FROM Ieee1609Dot2 {iso(1) identified-organization(3) ieee(111) 
  standards-association-numbered-series-standards(2) wave-stds(1609)  
  dot2(2) base(1) schema(1) major-version-2(2) minor-version-7(7)}

ExtensionModuleVersion
FROM EtsiTs103097ExtensionModule {itu-t(0) identified-organization(4)
  etsi(0) itsDomain(5) wg5(5) secHeaders(103097) extension(2) major-version-1(1) minor-version-2(2)}
;

EtsiTs103097Certificate::= Certificate (WITH COMPONENTS{...,
  issuer (WITH COMPONENTS{ -- constraints on issuer 
    sha256AndDigest,
    self (sha256 | sha384),
    sha384AndDigest
  }),
  toBeSigned (WITH COMPONENTS{...,
    id (WITH COMPONENTS{..., -- constraints on id 
      linkageData ABSENT,
      binaryId ABSENT
    }),
    certRequestPermissions ABSENT,
    canRequestRollover ABSENT,
    encryptionKey (WITH COMPONENTS { -- constraints on encryptionKey 
      supportedSymmAlg (aes128Ccm),
      publicKey (WITH COMPONENTS {
        eciesNistP256,
        eciesBrainpoolP256r1
      })
    }),
    verifyKeyIndicator (WITH COMPONENTS {..., -- constraints on verifyKeyIndicator 
      verificationKey (WITH COMPONENTS {
        ecdsaNistP256,
        ecdsaBrainpoolP256r1,
        ecdsaBrainpoolP384r1,
        ecdsaNistP384 
      })
    }) --,
   -- certRequestExtension ABSENT
  }),
  signature (WITH COMPONENTS { -- constraints on signature 
    ecdsaNistP256Signature,
    ecdsaBrainpoolP256r1Signature,
    ecdsaBrainpoolP384r1Signature,
    ecdsaNistP384Signature 
  })
}) 

EtsiTs103097Data::=Ieee1609Dot2Data (WITH COMPONENTS {..., 
  content (WITH COMPONENTS {...,
    signedData (WITH COMPONENTS {..., -- constraints on signed data headers
      hashId (sha256 | sha384),
      tbsData (WITH COMPONENTS {      -- constraints on tbsData       
        headerInfo (WITH COMPONENTS {...,
          generationTime PRESENT,
          p2pcdLearningRequest ABSENT,
          missingCrlIdentifier ABSENT,
          encryptionKey (WITH COMPONENTS { -- constraints on encryptionKey   
            public (WITH COMPONENTS {
              supportedSymmAlg (aes128Ccm),
              publicKey (WITH COMPONENTS {
                eciesNistP256,
                eciesBrainpoolP256r1
              })
            }),
            symmetric (WITH COMPONENTS {
              aes128Ccm  
            })
          })
        })
      }),
      signer (WITH COMPONENTS {...,  -- constraints on the certificate
        certificate ((WITH COMPONENT (EtsiTs103097Certificate))^(SIZE(1)))
      }),
      signature (WITH COMPONENTS {..., -- constraints on the signature
        sm2Signature ABSENT 
      })
    }),
    encryptedData (WITH COMPONENTS {..., -- constraints on encrypted data headers
      recipients  (WITH COMPONENT (
        (WITH COMPONENTS {...,
          certRecipInfo (WITH COMPONENTS{
            encKey (WITH COMPONENTS{
              eciesNistP256,
              eciesBrainpoolP256r1
            })
          }),
          signedDataRecipInfo(WITH COMPONENTS{
            encKey (WITH COMPONENTS{
              eciesNistP256,
              eciesBrainpoolP256r1
            })
          }),
          pskRecipInfo ABSENT,
          symmRecipInfo ABSENT,
          rekRecipInfo ABSENT
        })
      )),
      ciphertext (WITH COMPONENTS {
        aes128ccm
      })
    }),
    signedCertificateRequest ABSENT
  })
})

EtsiTs103097Data-Unsecured {ToBeSentDataContent} ::= EtsiTs103097Data (WITH COMPONENTS {...,
  content (WITH COMPONENTS {
    unsecuredData (CONTAINING ToBeSentDataContent)
  })
})

EtsiTs103097Data-Signed {ToBeSignedDataContent} ::= EtsiTs103097Data (WITH COMPONENTS {..., 
  content (WITH COMPONENTS {
    signedData (WITH COMPONENTS {..., 
      tbsData (WITH COMPONENTS { 
        payload (WITH COMPONENTS { 
          data (WITH COMPONENTS {...,
            content (WITH COMPONENTS {
              unsecuredData (CONTAINING ToBeSignedDataContent)
            })
          }) PRESENT
        })
      })
    })
  })
})

EtsiTs103097Data-SignedExternalPayload ::= EtsiTs103097Data (WITH COMPONENTS {..., 
  content (WITH COMPONENTS {
    signedData (WITH COMPONENTS {..., 
      tbsData (WITH COMPONENTS {
        payload (WITH COMPONENTS {
          extDataHash (WITH COMPONENTS {
            sha256HashedData PRESENT
          }) PRESENT
        })
      })
    })
  })
})

EtsiTs103097Data-Encrypted {ToBeEncryptedDataContent} ::= EtsiTs103097Data (WITH COMPONENTS {...,
  content (WITH COMPONENTS {
    encryptedData (WITH COMPONENTS {...,
      ciphertext (WITH COMPONENTS {...,
        aes128ccm (WITH COMPONENTS {...,
          ccmCiphertext (CONSTRAINED BY {-- ccm encryption of -- ToBeEncryptedDataContent}) 
        })
      })
    })
  })
})

EtsiTs103097Data-SignedAndEncrypted {ToBesignedAndEncryptedDataContent} ::= EtsiTs103097Data-Encrypted {EtsiTs103097Data-Signed {ToBesignedAndEncryptedDataContent}} 

EtsiTs103097Data-Encrypted-Unicast {ToBeEncryptedDataContent} ::= EtsiTs103097Data-Encrypted { EtsiTs103097Data-Unsecured{ToBeEncryptedDataContent}} (WITH COMPONENTS {...,
  content (WITH COMPONENTS {
    encryptedData (WITH COMPONENTS {...,
      recipients (SIZE(1))
    })
  })
})

EtsiTs103097Data-SignedAndEncrypted-Unicast {ToBesignedAndEncryptedDataContent} ::= EtsiTs103097Data-Encrypted {EtsiTs103097Data-Signed {ToBesignedAndEncryptedDataContent}} (WITH COMPONENTS {...,
  content (WITH COMPONENTS {
    encryptedData (WITH COMPONENTS {...,
      recipients (SIZE(1))
    })
  })
}) 

END
"""
