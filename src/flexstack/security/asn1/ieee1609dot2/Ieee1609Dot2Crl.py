# pylint: skip-file
IEEE_1609_DOT_2_CRL_ASN1_DESCRIPTIONS = """--***************************************************************************--
--                     IEEE Std 1609.2: CRL Data Types                       --
--***************************************************************************--

/**
 * @note Section references in this file are to clauses in IEEE Std
 * 1609.2 unless indicated otherwise. Full forms of acronyms and
 * abbreviations used in this file are specified in 3.2.
 */

Ieee1609Dot2Crl {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2)
  crl(3) major-version-3(3) minor-version-2(2)}

DEFINITIONS AUTOMATIC TAGS ::= BEGIN

IMPORTS
  Ieee1609Dot2Data
FROM Ieee1609Dot2 {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609)
  dot2(2) base(1) schema(1) major-version-2(2) minor-version-6(6)}

  Opaque,
  Psid
FROM Ieee1609Dot2BaseTypes {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2)
  base(1) base-types(2) major-version-2(2) minor-version-4(4)}

  CrlContents
FROM Ieee1609Dot2CrlBaseTypes {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2)
  crl(3) base-types(2) major-version-3(3) minor-version-2(2)}
;

/**
 * @brief This is the PSID for the CRL application.
 */
CrlPsid ::= Psid(256)

/**
 * @brief This structure is the SPDU used to contain a signed CRL. A valid 
 * signed CRL meets the validity criteria of 7.4.
 */
SecuredCrl ::= Ieee1609Dot2Data (WITH COMPONENTS {..., 
  content (WITH COMPONENTS {
    signedData  (WITH COMPONENTS {..., 
      tbsData (WITH COMPONENTS {
        payload (WITH COMPONENTS {..., 
          data (WITH COMPONENTS {...,
             content (WITH COMPONENTS {
                unsecuredData (CONTAINING CrlContents)
            })
          })
        }),
        headerInfo (WITH COMPONENTS {..., 
          psid (CrlPsid),
          generationTime ABSENT,
          expiryTime ABSENT,
          generationLocation ABSENT,
          p2pcdLearningRequest ABSENT,
          missingCrlIdentifier ABSENT,
          encryptionKey ABSENT
        })
      })
    })
  })
})

END
"""
