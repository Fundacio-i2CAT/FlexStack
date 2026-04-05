# pylint: skip-file
IEEE_1609_DOT_2_CRL_BASE_TYPES_ASN1_DESCRIPTIONS = """--***************************************************************************--
--                  IEEE Std 1609.2: CRL Base Data Types                     --
--***************************************************************************--

/**
 * @note Section references in this file are to clauses in IEEE Std
 * 1609.2 unless indicated otherwise. Full forms of acronyms and
 * abbreviations used in this file are specified in 3.2.
 */

Ieee1609Dot2CrlBaseTypes {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2)
  crl(3) base-types(2) major-version-3(3) minor-version-3(3)}

DEFINITIONS AUTOMATIC TAGS ::= BEGIN

IMPORTS
  CrlSeries,
  Duration,
  GeographicRegion,
  HashedId8,
  HashedId10,
  IValue,
  LaId,
  LinkageSeed,
  Opaque,
  Psid,
  SequenceOfLinkageSeed,
  Signature,
  Time32,
  Uint3,
  Uint8,
  Uint16,
  Uint32,
  ValidityPeriod
FROM Ieee1609Dot2BaseTypes {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2)
  base(1) base-types(2) major-version-2(2) minor-version-4(4)}
;

/**
 * @brief The fields in this structure have the following meaning:
 *
 * @param version: is the version number of the CRL. For this version of this
 * standard it is 1.
 *
 * @param crlSeries: represents the CRL series to which this CRL belongs. This
 * is used to determine whether the revocation information in a CRL is relevant
 * to a particular certificate as specified in 5.1.3.2.
 *
 * @param crlCraca: contains the low-order eight octets of the hash of the
 * certificate of the Certificate Revocation Authorization CA (CRACA) that
 * ultimately authorized the issuance of this CRL. This is used to determine
 * whether the revocation information in a CRL is relevant to a particular
 * certificate as specified in 5.1.3.2. In a valid signed CRL as specified in
 * 7.4 the crlCraca is consistent with the associatedCraca field in the
 * Service Specific Permissions as defined in 7.4.3.3. The HashedId8 is
 * calculated with the whole-certificate hash algorithm, determined as
 * described in 6.4.3, applied to the COER-encoded certificate, canonicalized 
 * as defined in the definition of Certificate.
 *
 * @param issueDate: specifies the time when the CRL was issued.
 *
 * @param nextCrl: contains the time when the next CRL with the same crlSeries
 * and cracaId is expected to be issued. The CRL is invalid unless nextCrl is
 * strictly after issueDate. This field is used to set the expected update time
 * for revocation information associated with the (crlCraca, crlSeries) pair as
 * specified in 5.1.3.6.
 *
 * @param priorityInfo: contains information that assists devices with limited
 * storage space in determining which revocation information to retain and
 * which to discard.
 *
 * @param	typeSpecific: contains the CRL body.
 */
CrlContents ::= SEQUENCE {
  version      Uint8 (1),
  crlSeries    CrlSeries,
  crlCraca     HashedId8,
  issueDate    Time32,   
  nextCrl      Time32,  
  priorityInfo CrlPriorityInfo,
  typeSpecific TypeSpecificCrlContents
}

/**
 * @brief This data structure contains information that assists devices with
 * limited storage space in determining which revocation information to retain
 * and which to discard.
 *
 * @param priority: indicates the priority of the revocation information
 * relative to other CRLs issued for certificates with the same cracaId and
 * crlSeries values. A higher value for this field indicates higher importance
 * of this revocation information.
 *
 * @note This mechanism is for future use; details are not specified in this
 * version of the standard.
 */
CrlPriorityInfo ::= SEQUENCE {  
  priority Uint8 OPTIONAL,
  ...
}

/**
 * @brief This structure contains type-specific CRL contents.
 *
 * @param fullHashCrl: contains a full hash-based CRL, i.e., a listing of the
 * hashes of all certificates that:
 *  - contain the indicated cracaId and crlSeries values, and
 *  - are revoked by hash, and
 *  - have been revoked
 *
 * @param deltaHashCrl: contains a delta hash-based CRL, i.e., a listing of
 * the hashes of all certificates that:
 *  - contain the indicated cracaId and crlSeries values, and
 *  - are revoked by hash, and
 *  - have been revoked since the previous CRL that contained the indicated
 * cracaId and crlSeries values.
 *
 * A Hash-based CRL should not include any certificates that had expired at the
 * time the CRL was generated; however, the inclusion of expired certificates
 * does not make a CRL invalid, and there is no expectation that receivers of a
 * CRL will check whether any of the certificates on the CRL have expired. 
 *
 * @note Since a recipient of a hash-based CRLonly receives the hash, they
 * cannot directly establish the validity period of any certificate on the CRL
 * without obtaining the certificate itself; this would render impractical any
 * validity check for CRLs based on the expiry status of the revoked
 * certificates.
 *
 * @param fullLinkedCrl and fullLinkedCrlWithAlg: contain a full linkage
 * ID-based CRL, i.e., a listing of the individual and/or group linkage data
 * for all certificates that:
 *  - contain the indicated cracaId and crlSeries values, and
 *  - are revoked by linkage value, and
 *  - have been revoked
 * The difference between fullLinkedCrl and fullLinkedCrlWithAlg is in how
 * the cryptographic algorithms to be used in the seed evolution function and
 * linkage value generation function of 5.1.3.4 are communicated to the
 * receiver of the CRL. See below in this subclause for details.
 *
 * @param deltaLinkedCrl and deltaLinkedCrlWithAlg: contain a delta linkage
 * ID-based CRL, i.e., a listing of the individual and/or group linkage data
 * for all certificates that:
 *  - contain the specified cracaId and crlSeries values, and
 *  -	are revoked by linkage data, and
 *  -	have been revoked since the previous CRL that contained the indicated
 * cracaId and crlSeries values.
 * The difference between deltaLinkedCrl and deltaLinkedCrlWithAlg is in how
 * the cryptographic algorithms to be used in the seed evolution function
 * and linkage value generation function of 5.1.3.4 are communicated to the
 * receiver of the CRL. See below in this subclause for details.
 *
 * @note It is the intent of this standard that once a certificate is revoked,
 * it remains revoked for the rest of its lifetime. CRL signers are expected 
 * to include a revoked certificate on all CRLs issued between the 
 * certificate's revocation and its expiry.
 *
 * @note Seed evolution function and linkage value generation function
 * identification. In order to derive linkage values per the mechanisms given
 * in 5.1.3.4, a receiver needs to know the seed evolution function and the
 * linkage value generation function.
 *
 * If the contents of this structure is a
 * ToBeSignedLinkageValueCrlWithAlgIdentifier, then the seed evolution function
 * and linkage value generation function are given explicitly as specified in
 * the specification of ToBeSignedLinkageValueCrlWithAlgIdentifier.
 *
 * If the contents of this structure is a ToBeSignedLinkageValueCrl, then the
 * seed evolution function and linkage value generation function are obtained
 * based on the crlCraca field in the CrlContents:
 *  - If crlCraca was obtained with SHA-256 or SHA-384, then
 * seedEvolutionFunctionIdentifier is seedEvoFn1-sha256 and
 * linkageValueGenerationFunctionIdentifier is lvGenFn1-aes128.
 *  - If crlCraca was obtained with SM3, then seedEvolutionFunctionIdentifier
 * is seedEvoFn1-sm3 and linkageValueGenerationFunctionIdentifier is
 * lvGenFn1-sm4.
 */
TypeSpecificCrlContents ::= CHOICE {
  fullHashCrl           ToBeSignedHashIdCrl,            
  deltaHashCrl          ToBeSignedHashIdCrl,            
  fullLinkedCrl         ToBeSignedLinkageValueCrl,
  deltaLinkedCrl        ToBeSignedLinkageValueCrl,
  ...,
  fullLinkedCrlWithAlg  ToBeSignedLinkageValueCrlWithAlgIdentifier,
  deltaLinkedCrlWithAlg ToBeSignedLinkageValueCrlWithAlgIdentifier
}

/**
 * @brief This data structure represents information about a revoked
 * certificate.
 *
 * @param crlSerial: is a counter that increments by 1 every time a new full
 * or delta CRL is issued for the indicated crlCraca and crlSeries values.  A
 * "new full or delta CRL" is a CRL with a new issueDate, whether or not the
 * contents of the CRL have changed.
 *
 * @param entries: contains the individual revocation information items.
 *
 * @note To indicate that a hash-based CRL contains no individual revocation 
 * information items, the recommended approach is for the SEQUENCE OF in the 
 * SequenceOfHashBasedRevocationInfo in this field to indicate zero entries.
 */
ToBeSignedHashIdCrl ::= SEQUENCE {  
  crlSerial Uint32,
  entries   SequenceOfHashBasedRevocationInfo,
  ...
}

/**
 * @brief This type is used for clarity of definitions.
 */
SequenceOfHashBasedRevocationInfo ::= 
  SEQUENCE OF HashBasedRevocationInfo 

/**
 * @brief In this structure:
 *
 * @param	id: is the HashedId10 identifying the revoked certificate. The 
 * HashedId10 is calculated with the whole-certificate hash algorithm, 
 * determined as described in 6.4.3, applied to the COER-encoded certificate,
 * canonicalized as defined in the definition of Certificate.
 *
 * @param expiry: is the value computed from the validity period's start and
 * duration values in that certificate.
 */
HashBasedRevocationInfo ::= SEQUENCE {
  id     HashedId10,
  expiry Time32,
  ...
}

/**
 * @brief In this structure:
 *
 * @param	iRev: is the value iRev used in the algorithm given in 5.1.3.4. This
 * value applies to all linkage-based revocation information included within
 * either indvidual or groups.
 *
 * @param	indexWithinI: is a counter that is set to 0 for the first CRL issued
 * for the indicated combination of crlCraca, crlSeries, and iRev, and
 * increments by 1 every time a new full or delta CRL is issued for the
 * indicated crlCraca and crlSeries values without changing iRev.
 *
 * @param individual: contains individual linkage data.
 *
 * @note To indicate that a linkage ID-based CRL contains no individual
 * linkage data, the recommended approach is for the SEQUENCE OF in the
 * SequenceOfJMaxGroup in this field to indicate zero entries.
 *
 * @param groups: contains group linkage data.
 *
 * @note To indicate that a linkage ID-based CRL contains no group linkage
 * data, the recommended approach is for the SEQUENCE OF in the
 * SequenceOfGroupCrlEntry in this field to indicate zero entries.
 *
 * @param groupsSingleSeed: contains group linkage data generated with a single 
 * seed.
 *
 * @param iPeriodInfo contains information about the duration of the revocation
 * time periods, to allow a receiver to determine at what point it will be
 * necessary to have calculated the linkage values associated with future time
 * periods.
 */
ToBeSignedLinkageValueCrl ::= SEQUENCE {  
  iRev             IValue,
  indexWithinI     Uint8,
  individual       SequenceOfJMaxGroup OPTIONAL,
  groups           SequenceOfGroupCrlEntry OPTIONAL,
  ...,
  groupsSingleSeed SequenceOfGroupSingleSeedCrlEntry OPTIONAL,
  iPeriodInfo      SequenceOfIPeriodInfo OPTIONAL
} (WITH COMPONENTS {..., individual PRESENT} |
   WITH COMPONENTS {..., groups PRESENT} |
   WITH COMPONENTS {..., groupsSingleSeed PRESENT})

/**
 * @brief This type is used for clarity of definitions.
 */
SequenceOfJMaxGroup ::= SEQUENCE OF JMaxGroup

/**
 * @brief In this structure:
 *
 * @param	jMax: is the value jMax used in the algorithm given in 5.1.3.4. This
 * value applies to all linkage-based revocation information included within
 * contents.
 *
 * @param contents: contains individual linkage data.
 */
JMaxGroup ::= SEQUENCE {
  jmax     Uint8,
  contents SequenceOfLAGroup,
  ...
}

/**
 * @brief This type is used for clarity of definitions.
 */
SequenceOfLAGroup ::= SEQUENCE OF LAGroup

/**
 * @brief In this structure:
 *
 * @param la1Id: is the value LinkageAuthorityIdentifier1 used in the
 * algorithm given in 5.1.3.4. This value applies to all linkage-based
 * revocation information included within contents.
 *
 * @param la2Id: is the value LinkageAuthorityIdentifier2 used in the
 * algorithm given in 5.1.3.4. This value applies to all linkage-based
 * revocation information included within contents.
 *
 * @param contents: contains individual linkage data.
 */
LAGroup ::= SEQUENCE {
  la1Id    LaId,
  la2Id    LaId,
  contents SequenceOfIMaxGroup,
  ...
}

/**
 * @brief This type is used for clarity of definitions.
 */
SequenceOfIMaxGroup ::= SEQUENCE OF IMaxGroup

/**
 * @brief In this structure:
 *
 * @param iMax indicates that for the entries in contents, revocation 
 * information need no longer be calculated once iCert > iMax as the holder 
 * is known to have no more valid certs at that point. iMax is not directly 
 * used in the calculation of the linkage values, it is used to determine 
 * when revocation information can safely be deleted.
 *
 * @param contents contains individual linkage data for certificates that are 
 * revoked using two seeds, per the algorithm given in per the mechanisms 
 * given in 5.1.3.4 and with seedEvolutionFunctionIdentifier and 
 * linkageValueGenerationFunctionIdentifier obtained as specified in 7.3.3.
 *
 * @param singleSeed contains individual linkage data for certificates that 
 * are revoked using a single seed, per the algorithm given in per the 
 * mechanisms given in 5.1.3.4 and with seedEvolutionFunctionIdentifier and 
 * linkageValueGenerationFunctionIdentifier obtained as specified in 7.3.3.
 */
IMaxGroup ::= SEQUENCE {
  iMax       Uint16,
  contents   SequenceOfIndividualRevocation,
  ...,
  singleSeed SequenceOfLinkageSeed OPTIONAL
}

/**
 * @brief This type is used for clarity of definitions.
 */
SequenceOfIndividualRevocation ::= 
  SEQUENCE (SIZE(0..MAX)) OF IndividualRevocation

/**
 * @brief In this structure:
 *
 * @param linkageSeed1 is the value LinkageSeed1 used in the algorithm given 
 * in 5.1.3.4.
 *
 * @param linkageSeed2 is the value LinkageSeed2 used in the algorithm given 
 * in 5.1.3.4.
 */ 
IndividualRevocation ::= SEQUENCE { 
  linkageSeed1 LinkageSeed,
  linkageSeed2 LinkageSeed,
  ...
}

/**
 * @brief This type is used for clarity of definitions.
 */
SequenceOfGroupCrlEntry ::= SEQUENCE OF GroupCrlEntry

/**
 * @brief In this structure:
 *
 * @param iMax: indicates that for these certificates, revocation information 
 * need no longer be calculated once iCert > iMax as the holders are known 
 * to have no more valid certs for that (crlCraca, crlSeries) at that point.
 *
 * @param la1Id: is the value LinkageAuthorityIdentifier1 used in the 
 * algorithm given in 5.1.3.4. This value applies to all linkage-based 
 * revocation information included within contents.
 *
 * @param linkageSeed1: is the value LinkageSeed1 used in the algorithm given 
 * in 5.1.3.4.
 *
 * @param la2Id: is the value LinkageAuthorityIdentifier2 used in the 
 * algorithm given in 5.1.3.4. This value applies to all linkage-based 
 * revocation information included within contents.
 *
 * @param linkageSeed2: is the value LinkageSeed2 used in the algorithm given 
 * in 5.1.3.4.
 */
GroupCrlEntry ::= SEQUENCE {
  iMax         Uint16,
  la1Id        LaId,
  linkageSeed1 LinkageSeed,
  la2Id        LaId,
  linkageSeed2 LinkageSeed,
  ...
}

/**
 * @brief In this structure:
 * 
 * @param iRev is the value iRev used in the algorithm given in 5.1.3.4. This 
 * value applies to all linkage-based revocation information included within 
 * either indvidual or groups.
 * 
 * @param indexWithinI is a counter that is set to 0 for the first CRL issued 
 * for the indicated combination of crlCraca, crlSeries, and iRev, and increments
 * by 1 every time a new full or delta CRL is issued for the indicated crlCraca 
 * and crlSeries values without changing iRev.
 * 
 * @param seedEvolution contains an identifier for the seed evolution 
 * function, used as specified in  5.1.3.4.
 * 
 * @param lvGeneration contains an identifier for the linkage value 
 * generation function, used as specified in  5.1.3.4.
 * 
 * @param individual contains individual linkage data.
 * 
 * @param groups contains group linkage data for linkage value generation 
 * with two seeds.
 * 
 * @param groupsSingleSeed contains group linkage data for linkage value 
 * generation with one seed.
 *
 * @param iPeriodInfo contains information about the duration of the 
 * revocation time periods, to allow a receiver to determine at what point
 * it will be necessary to have calculated the linkage values associated
 * with future time periods.
 */
ToBeSignedLinkageValueCrlWithAlgIdentifier ::= SEQUENCE {  
  iRev             IValue,
  indexWithinI     Uint8,
  seedEvolution    SeedEvolutionFunctionIdentifier,
  lvGeneration     LvGenerationFunctionIdentifier,
  individual       SequenceOfJMaxGroup OPTIONAL,
  groups           SequenceOfGroupCrlEntry OPTIONAL,
  groupsSingleSeed SequenceOfGroupSingleSeedCrlEntry OPTIONAL,
  ...
} (WITH COMPONENTS {..., individual PRESENT} |
   WITH COMPONENTS {..., groups PRESENT} |
   WITH COMPONENTS {..., groupsSingleSeed PRESENT})

/**
 * @brief This type is used for clarity of definitions.
 */
SequenceOfGroupSingleSeedCrlEntry ::= 
  SEQUENCE OF GroupSingleSeedCrlEntry

/**
 * @brief This structure contains the linkage seed for group revocation with 
 * a single seed. The seed is used as specified in the algorithms in 5.1.3.4.
 */
GroupSingleSeedCrlEntry ::= SEQUENCE {
  iMax        Uint16,
  laId        LaId,
  linkageSeed LinkageSeed
}

/**
 * @brief This structure contains an identifier for the algorithms specified 
 * in 5.1.3.4.
 */
ExpansionAlgorithmIdentifier ::= ENUMERATED {
  sha256ForI-aesForJ,
  sm3ForI-sm4ForJ,
  ...
}

/**
 * @brief This is the identifier for the seed evolution function. See 5.1.3 
 * for details of use.
 */
SeedEvolutionFunctionIdentifier ::= NULL

/**
 * @brief This is the identifier for the linkage value generation function. 
 * See 5.1.3 for details of use.
 */
LvGenerationFunctionIdentifier ::= NULL

/**
 * @brief This structure contains information about when future revocation
 * time periods start. Revocation time periods are discussed in 5.1.3.4.
 * Linkage value based CRLs contain linkage seeds which can be used to
 * calculate the linkage values that will appear in certificates for
 * revocation time periods that are in the future relative to the issuance
 * time of the CRL; the IPeriodInfo structure allows the CRL signer to
 * communicate the start time for future time periods, so that a CRL recipient
 * can calculate the linkage values before the relevant time period starts.
 * The CRL contains a SEQUENCE of IPeriodInfo to support the case where the
 * CRL issuer knows that the duration of the time periods is going to change
 * at some point in the future; the number of IPeriodInfo in the sequence
 * should be the minimum necessary to convey the information, e.g. if the
 * duration of the time periods is not going to change, the CRL should contain
 * a single IPeriodInfo.
 * 
 * @note The information about the duration of future time periods can be
 * assumed to be available to the CRL signer, because pseudonym certificates
 * that use linkage values are typically issued for future time periods rather
 * than only the current time period, and so the length of future time periods
 * had to be known to the CA at the time of certificate issuance and can be
 * provided to the CRL signer. This creates a requirement that if multiple CAs
 * issue certificates that use the same CRL Series and CRACA Id values, all of
 * those CAs will be expected to implement any time period length changes in
 * synch with each other so that all certificates on the same CRL will have
 * synchronized time period starts and ends. How these CAs are synchronized
 * with each other is out of scope for this document.
 * 
 * An IPeriodInfo appears in a CRL that has an iRev field. The CRL contains a
 * SEQUENCE of IPeriodInfo. Each IPeriodInfo makes use of the previous iRev
 * value, prevI. For the first IPeriodInfo in the SEQUENCE, prevI is the value
 * of iRev in the CRL. For each subsequent IPeriodInfo in the SEQUENCE, prevI
 * is the value of guaranteedToIValue in the previous IPeriodInfo. 
 * 
 * In this structure:
 *
 * @param startOfNextIPeriod is the start time of the i-period with i = prevI +
 * 1. This is the earliest time at which certificates with i-period equal to
 * prevI + 1 will be valid, i.e. if a certificate with the cracaId and
 * crlSeries corresponding to this CRL has
 * ToBeSignedCertificate.id.linkageData.iCert = prevI + 1, then
 * ToBeSignedCertificate.validityPeriod.start will be no earlier than this
 * startOfNextIPeriod value.
 *
 * @param iPeriodLength is the length of all time periods from prevI + 1 to
 * guaranteedToIValue inclusive, i.e., each time period starts exactly
 * iPeriodLength after the previous time period started.
 *
 * @param guaranteedToIValue is last i-period which is guaranteed to have the
 * indicated duration, i.e., all time periods from prevI + 1 to
 * guaranteedToIValue are guaranteed to have that duration and time period
 * guaranteedToIValue +1 is not guaranteed to have that duration.
 */

IPeriodInfo ::= SEQUENCE {
  startOfNextIPeriod     Time32,
  iPeriodLength          Duration,
  guaranteedToIValue     IValue
}

SequenceOfIPeriodInfo ::= SEQUENCE OF IPeriodInfo



END
"""
