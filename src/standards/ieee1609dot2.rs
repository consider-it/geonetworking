//! Message types from IEEE 1609.2

pub use rasn_its::ieee1609dot2::AppExtension;
pub use rasn_its::ieee1609dot2::CertIssueExtension;
pub use rasn_its::ieee1609dot2::CertRequestExtension;
pub use rasn_its::ieee1609dot2::IssuePermissions as CertIssueExtensionPermissions;
pub use rasn_its::ieee1609dot2::IssuePermissions as CertRequestExtensionPermissions;

pub use rasn_its::ieee1609dot2::Certificate;
pub use rasn_its::ieee1609dot2::CertificateBase;
pub use rasn_its::ieee1609dot2::CertificateId;
pub use rasn_its::ieee1609dot2::CertificateType;

// impl TryFrom<i128> for CertificateType {
//     type Error = ();

//     fn try_from(value: i128) -> Result<Self, Self::Error> {
//         match value {
//             0 => Ok(CertificateType::Explicit),
//             1 => Ok(CertificateType::Implicit),
//             _ => Err(()),
//         }
//     }
// }

pub use rasn_its::ieee1609dot2::ContributedExtensionBlock;
pub use rasn_its::ieee1609dot2::ContributedExtensionBlocks;
pub use rasn_its::ieee1609dot2::Countersignature;
pub use rasn_its::ieee1609dot2::Ieee1609Dot2Data;

//**************************************************************************
//                              Encrypted Data
//**************************************************************************

pub use rasn_its::ieee1609dot2::EncryptedData;
pub use rasn_its::ieee1609dot2::EncryptedDataEncryptionKey;
pub use rasn_its::ieee1609dot2::EndEntityType;

// impl From<Vec<bool>> for EndEntityType {
//     fn from(value: Vec<bool>) -> Self {
//         Self(value.into())
//     }
// }

// impl From<[bool; 8]> for EndEntityType {
//     fn from(value: [bool; 8]) -> Self {
//         Self(value.into())
//     }
// }

// impl EndEntityType {
//     // bit 0
//     #[must_use]
//     pub fn has_app(&self) -> bool {
//         self.0 .0[0]
//     }

//     // bit 1
//     #[must_use]
//     pub fn has_enrol(&self) -> bool {
//         self.0 .0[1]
//     }
// }

pub use rasn_its::ieee1609dot2::ExplicitCertificate;
pub use rasn_its::ieee1609dot2::HashedData;
pub use rasn_its::ieee1609dot2::HeaderInfo;
pub use rasn_its::ieee1609dot2::HeaderInfoContributorId;
pub use rasn_its::ieee1609dot2::Ieee1609ContributedHeaderInfoExtension;
pub use rasn_its::ieee1609dot2::Ieee1609Dot2Content;

//**************************************************************************
//                               Secured Data
//**************************************************************************

pub type Ieee1609HeaderInfoExtensionId = rasn_its::ts103097::extension_module::ExtId;
pub use rasn_its::ieee1609dot2::ImplicitCertificate;
pub use rasn_its::ieee1609dot2::IssuerIdentifier;
pub use rasn_its::ieee1609dot2::LinkageData;
pub use rasn_its::ieee1609dot2::MissingCrlIdentifier;
pub use rasn_its::ieee1609dot2::One28BitCcmCiphertext;
pub use rasn_its::ieee1609dot2::OperatingOrganizationId;
pub use rasn_its::ieee1609dot2::PKRecipientInfo;
pub use rasn_its::ieee1609dot2::PduFunctionalType;
pub use rasn_its::ieee1609dot2::PreSharedKeyRecipientInfo;
pub use rasn_its::ieee1609dot2::PsidGroupPermissions;
pub use rasn_its::ieee1609dot2::RecipientInfo;
pub use rasn_its::ieee1609dot2::SequenceOfAppExtensions;
pub use rasn_its::ieee1609dot2::SequenceOfCertIssueExtensions;
pub use rasn_its::ieee1609dot2::SequenceOfCertRequestExtensions;
pub use rasn_its::ieee1609dot2::SequenceOfCertificate;
pub use rasn_its::ieee1609dot2::SequenceOfPsidGroupPermissions;
pub use rasn_its::ieee1609dot2::SequenceOfRecipientInfo;
pub use rasn_its::ieee1609dot2::SignedData;
pub use rasn_its::ieee1609dot2::SignedDataPayload;
pub use rasn_its::ieee1609dot2::SignerIdentifier;
pub use rasn_its::ieee1609dot2::SubjectPermissions;
pub use rasn_its::ieee1609dot2::SymmRecipientInfo;
pub use rasn_its::ieee1609dot2::SymmetricCiphertext;
pub use rasn_its::ieee1609dot2::TestCertificate;
pub use rasn_its::ieee1609dot2::ToBeSignedCertificate;
pub use rasn_its::ieee1609dot2::ToBeSignedData;
pub use rasn_its::ieee1609dot2::VerificationKeyIndicator;
// pub const CERT_EXT_ID_OPERATING_ORGANIZATION: ExtId = ExtId(1);
// pub const ETSI_HEADER_INFO_CONTRIBUTOR_ID: HeaderInfoContributorId = HeaderInfoContributorId(2);
// pub const IEEE1609HEADER_INFO_CONTRIBUTOR_ID: HeaderInfoContributorId = HeaderInfoContributorId(1);
// pub const ISO21177EXTENDED_AUTH: PduFunctionalType = PduFunctionalType(2);
// pub const ISO21177SESSION_EXTENSION: PduFunctionalType = PduFunctionalType(3);
// pub const P2PCD8BYTE_LEARNING_REQUEST_ID: Ieee1609HeaderInfoExtensionId = ExtId(1);
// pub const TLS_HANDSHAKE: PduFunctionalType = PduFunctionalType(1);
pub use rasn_its::ieee1609dot2::base_types::BasePublicEncryptionKey;
pub use rasn_its::ieee1609dot2::base_types::BitmapSsp;
pub use rasn_its::ieee1609dot2::base_types::BitmapSspRange;
pub use rasn_its::ieee1609dot2::base_types::CircularRegion;
pub use rasn_its::ieee1609dot2::base_types::CountryAndRegions;
pub use rasn_its::ieee1609dot2::base_types::CountryAndSubregions;
pub use rasn_its::ieee1609dot2::base_types::CountryOnly;
pub use rasn_its::ieee1609dot2::base_types::CrlSeries;
pub use rasn_its::ieee1609dot2::base_types::Duration;
pub use rasn_its::ieee1609dot2::base_types::EccP256CurvePoint;
pub use rasn_its::ieee1609dot2::base_types::EccP256CurvePointUncompressedP256;
pub use rasn_its::ieee1609dot2::base_types::EccP384CurvePoint;
pub use rasn_its::ieee1609dot2::base_types::EccP384CurvePointUncompressedP384;
pub use rasn_its::ieee1609dot2::base_types::EcdsaP256Signature;
pub use rasn_its::ieee1609dot2::base_types::EcdsaP384Signature;
pub use rasn_its::ieee1609dot2::base_types::EcencP256EncryptedKey;
pub use rasn_its::ieee1609dot2::base_types::EciesP256EncryptedKey;
pub use rasn_its::ieee1609dot2::base_types::EcsigP256Signature;
pub use rasn_its::ieee1609dot2::base_types::Elevation;
pub use rasn_its::ieee1609dot2::base_types::EncryptionKey;
pub use rasn_its::ts103097::extension_module::ExtId;
pub use rasn_its::ts103097::extension_module::Extension;

//**************************************************************************
//                           Location Structures
//**************************************************************************

/// represents a geographic region of a specified form
///
/// A certificate is not valid if any part of the region indicated in its
/// scope field lies outside the region indicated in the scope of its issuer.
///
/// Note: Critical information fields:
///   - If present, this is a critical information field as defined in 5.2.6.
///
/// An implementation that does not recognize the indicated CHOICE when
/// verifying a signed SPDU shall indicate that the signed SPDU is invalid in
/// the sense of 4.2.2.3.2, that is, it is invalid in the sense that its
/// validity cannot be established.
///   - If selected, rectangularRegion is a critical information field as
///     defined in 5.2.6. An implementation that does not support the number of
///     `RectangularRegion` in rectangularRegions when verifying a signed SPDU shall
///     indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2, that
///     is, it is invalid in the sense that its validity cannot be established.
///     A conformant implementation shall support rectangularRegions fields
///     containing at least eight entries.
///   - If selected, identifiedRegion is a critical information field as
///     defined in 5.2.6. An implementation that does not support the number of
///     `IdentifiedRegion` in identifiedRegion shall reject the signed SPDU as
///     invalid in the sense of 4.2.2.3.2, that is, it is invalid in the sense
///     that its validity cannot be established. A conformant implementation shall
///     support identifiedRegion fields containing at least eight entries.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum GeographicRegion {
    /// contains a single instance of the `CircularRegion` structure
    CircularRegion(CircularRegion),

    /// is an array of `RectangularRegion` structures containing at least one entry.
    /// This field is interpreted as a series of rectangles, which may overlap or be disjoint.
    /// The permitted region is any point within any of the rectangles.
    RectangularRegion(SequenceOfRectangularRegion),

    /// contains a single instance of the `PolygonalRegion` structure
    PolygonalRegion(PolygonalRegion),

    /// is an array of `IdentifiedRegion` structures containing at least one entry.
    /// The permitted region is any point within any of the identified regions.
    IdentifiedRegion(SequenceOfIdentifiedRegion),
}

/// This is the group linkage value
///
/// See 5.1.3 and 7.3 for details of
/// use.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct GroupLinkageValue<'input> {
    #[cfg_attr(feature = "serde", serde(borrow))]
    pub j_value: &'input [u8],
    #[cfg_attr(feature = "serde", serde(borrow))]
    pub value: &'input [u8],
}

/// identifies a hash algorithm
///
/// The value sha256, indicates SHA-256. The value sha384 indicates SHA-384. The
/// value sm3 indicates SM3. See 5.3.3 for more details.
///
/// Note: Critical information fields: This is a critical information field as
/// defined in 5.2.6. An implementation that does not recognize the enumerated
/// value of this type in a signed SPDU when verifying a signed SPDU shall
/// indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2, that
/// is, it is invalid in the sense that its validity cannot be established.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum HashAlgorithm {
    Sha256 = 0,
    Sha384 = 1,
    Sm3 = 2,
}

impl TryFrom<i128> for HashAlgorithm {
    type Error = ();

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(HashAlgorithm::Sha256),
            1 => Ok(HashAlgorithm::Sha384),
            2 => Ok(HashAlgorithm::Sm3),
            _ => Err(()),
        }
    }
}

/// contains the truncated hash of another data structure
///
/// The `HashedId10` for a given data structure is calculated by calculating the
/// hash of the encoded data structure and taking the low-order ten bytes of
/// the hash output. The low-order ten bytes are the last ten bytes of the
/// hash when represented in network byte order. If the data structure
/// is subject to canonicalization it is canonicalized before hashing. See
/// Example below.
///
/// The hash algorithm to be used to calculate a `HashedId10` within a
/// structure depends on the context. In this standard, for each structure
/// that includes a `HashedId10` field, the corresponding text indicates how the
/// hash algorithm is determined. See also the discussion in 5.3.9.
/// Example: Consider the SHA-256 hash of the empty string:
/// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
///
/// The `HashedId10` derived from this hash corresponds to the following:
/// `HashedId10` = 934ca495991b7852b855.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct HashedId10<'input>(#[cfg_attr(feature = "serde", serde(borrow))] pub &'input [u8]);

/// contains the truncated hash of another data structure
///
/// The `HashedId3` for a given data structure is calculated by calculating the
/// hash of the encoded data structure and taking the low-order three bytes of
/// the hash output. The low-order three bytes are the last three bytes of the
/// 32-byte hash when represented in network byte order. If the data structure
/// is subject to canonicalization it is canonicalized before hashing. See
/// Example below.
///
/// The hash algorithm to be used to calculate a `HashedId3` within a
/// structure depends on the context. In this standard, for each structure
/// that includes a `HashedId3` field, the corresponding text indicates how the
/// hash algorithm is determined. See also the discussion in 5.3.9.
///
/// Example: Consider the SHA-256 hash of the empty string:
/// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
/// The `HashedId3` derived from this hash corresponds to the following:
/// `HashedId3` = 52b855.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct HashedId3<'input>(#[cfg_attr(feature = "serde", serde(borrow))] pub &'input [u8]);

/// Truncated hash of another data structure
///
/// The `HashedId32` for a given data structure is calculated by
/// calculating the hash of the encoded data structure and taking the
/// low-order 32 bytes of the hash output. The low-order 32 bytes are the last
/// 32 bytes of the hash when represented in network byte order. If the data
/// structure is subject to canonicalization it is canonicalized before
/// hashing. See Example below.
/// The hash algorithm to be used to calculate a `HashedId32` within a
/// structure depends on the context. In this standard, for each structure
/// that includes a `HashedId32` field, the corresponding text indicates how the
/// hash algorithm is determined. See also the discussion in 5.3.9.
///
/// Example: Consider the SHA-256 hash of the empty string:
/// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
///
/// The `HashedId32` derived from this hash corresponds to the following:
/// `HashedId32` = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct HashedId32<'input>(#[cfg_attr(feature = "serde", serde(borrow))] pub &'input [u8]);

/// Truncated hash of another data structure
///
/// The `HashedId48` for a given data structure is calculated by
/// calculating the hash of the encoded data structure and taking the
/// low-order 48 bytes of the hash output. The low-order 48 bytes are the last
/// 48 bytes of the hash when represented in network byte order. If the data
/// structure is subject to canonicalization it is canonicalized before
/// hashing. See Example below.
///
/// The hash algorithm to be used to calculate a `HashedId48` within a
/// structure depends on the context. In this standard, for each structure
/// that includes a `HashedId48` field, the corresponding text indicates how the
/// hash algorithm is determined. See also the discussion in 5.3.9.
///
/// Example: Consider the SHA-384 hash of the empty string:
/// SHA-384("") = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6 e1da274edebfe76f65fbd51ad2f14898b95b
/// The `HashedId48` derived from this hash corresponds to the following:
/// `HashedId48` = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e
/// 1da274edebfe76f65fbd51ad2f14898b95b.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct HashedId48<'input>(#[cfg_attr(feature = "serde", serde(borrow))] pub &'input [u8]);

/// contains the truncated hash of another data structure
///
/// The `HashedId8` for a given data structure is calculated by calculating the
/// hash of the encoded data structure and taking the low-order eight bytes of
/// the hash output. The low-order eight bytes are the last eight bytes of the
/// hash when represented in network byte order. If the data structure
/// is subject to canonicalization it is canonicalized before hashing. See
/// Example below.
///
/// The hash algorithm to be used to calculate a `HashedId8` within a
/// structure depends on the context. In this standard, for each structure
/// that includes a `HashedId8` field, the corresponding text indicates how the
/// hash algorithm is determined. See also the discussion in 5.3.9.
///
/// Example: Consider the SHA-256 hash of the empty string:
/// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
/// The `HashedId8` derived from this hash corresponds to the following:
/// `HashedId8` = a495991b7852b855.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct HashedId8<'input>(#[cfg_attr(feature = "serde", serde(borrow))] pub &'input [u8]);

/// UTF-8 string as defined in IETF RFC 3629
///
/// The contents are determined by policy.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Hostname(pub String);

//**************************************************************************
//                             Pseudonym Linkage
//**************************************************************************

/// This atomic type is used in the definition of other data structures
pub type IValue = Uint16;

/// indicates the region of validity of a certificate using region identifiers
///
/// A conformant implementation that supports this type shall support at least
/// one of the possible CHOICE values. The Protocol Implementation Conformance
/// Statement (PICS) provided in Annex A allows an implementation to state
/// which `CountryOnly` values it recognizes.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum IdentifiedRegion {
    /// indicates that only a country (or a geographic entity included in a country list) is given
    CountryOnly(UnCountryId),

    /// indicates that one or more top-level regions
    /// within a country (as defined by the region listing associated with that
    /// country) is given.
    CountryAndRegions(CountryAndRegions),

    /// indicates that one or more regions smaller
    /// than the top-level regions within a country (as defined by the region
    /// listing associated with that country) is given.
    /// Critical information fields: If present, this is a critical
    /// information field as defined in 5.2.6. An implementation that does not
    /// recognize the indicated CHOICE when verifying a signed SPDU shall indicate
    /// that the signed SPDU is invalid in the sense of 4.2.2.3.2, that is, it is
    /// invalid in the sense that its validity cannot be established.
    CountryAndSubregions(CountryAndSubregions),
}

/// The known latitudes are from -900,000,000 to +900,000,000 in 0.1 microdegree intervals
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct KnownLatitude(pub NinetyDegreeInt);

/// The known longitudes are from -1,799,999,999 to +1,800,000,000 in 0.1 microdegree intervals
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct KnownLongitude(pub OneEightyDegreeInt);

/// contains a LA Identifier for use in the algorithms specified in 5.1.3.4
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct LaId<'input>(#[cfg_attr(feature = "serde", serde(borrow))] pub &'input [u8]);

/// Estimate of the latitude with precision 1/10th microdegree
///
/// This type contains an INTEGER encoding an estimate of the latitude
/// with precision 1/10th microdegree relative to the World Geodetic System
/// (WGS)-84 datum as defined in NIMA Technical Report TR8350.2.
/// The integer in the latitude field is no more than 900 000 000 and no less
/// than ?900 000 000, except that the value 900 000 001 is used to indicate
/// the latitude was not available to the sender.
pub type Latitude = NinetyDegreeInt;

/// contains a linkage seed value for use in the algorithms specified in 5.1.3.4
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct LinkageSeed<'input>(#[cfg_attr(feature = "serde", serde(borrow))] pub &'input [u8]);

/// This is the individual linkage value
///
/// See 5.1.3 and 7.3 for details of use.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct LinkageValue<'input>(#[cfg_attr(feature = "serde", serde(borrow))] pub &'input [u8]);

/// Estimate of the longitude with precision 1/10th microdegree
///
/// This type contains an INTEGER encoding an estimate of the longitude
/// with precision 1/10th microdegree relative to the World Geodetic System
/// (WGS)-84 datum as defined in NIMA Technical Report TR8350.2.
/// The integer in the longitude field is no more than 1 800 000 000 and no
/// less than ?1 799 999 999, except that the value 1 800 000 001 is used to
/// indicate that the longitude was not available to the sender.
pub type Longitude = OneEightyDegreeInt;

/// See [`Latitude`]
///
/// The integer in the latitude field is no more than 900,000,000 and
/// no less than -900,000,000, except that the value 900,000,001 is used to
/// indicate the latitude was not available to the sender.
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct NinetyDegreeInt(pub i32);

/// See [`Longitude`]
///
/// The integer in the longitude field is no more than 1,800,000,000
/// and no less than -1,799,999,999, except that the value 1,800,000,001 is
/// used to indicate that the longitude was not available to the sender.
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct OneEightyDegreeInt(pub i32);

//**************************************************************************
//                            OCTET STRING Types
//**************************************************************************

/// synonym for ASN.1 OCTET STRING, and is used in the definition of other data structures
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Opaque<'input>(#[cfg_attr(feature = "serde", serde(borrow))] pub &'input [u8]);

/// defines a region using a series of distinct geographic points, defined on the surface of the reference ellipsoid
///
/// The region is specified by connecting the points in the order they appear,
/// with each pair of points connected by the geodesic on the reference
/// ellipsoid. The polygon is completed by connecting the final point to the
/// first point. The allowed region is the interior of the polygon and its
/// boundary.
///
/// A point which contains an elevation component is considered to be
/// within the polygonal region if its horizontal projection onto the
/// reference ellipsoid lies within the region.
/// A valid `PolygonalRegion` contains at least three points. In a valid
/// `PolygonalRegion`, the implied lines that make up the sides of the polygon
/// do not intersect.
///
/// Note: This type does not support enclaves / exclaves. This might be
/// addressed in a future version of this standard.
///
/// Note: Critical information fields: If present, this is a critical
/// information field as defined in 5.2.6. An implementation that does not
/// support the number of `TwoDLocation` in the `PolygonalRegion` when verifying a
/// signed SPDU shall indicate that the signed SPDU is invalid. A compliant
/// implementation shall support `PolygonalRegions` containing at least eight
/// `TwoDLocation` entries.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct PolygonalRegion(pub Vec<TwoDLocation>);

/// represents the PSID defined in IEEE Std 1609.12
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Psid(pub u128);

//**************************************************************************
//                              PSID / ITS-AID
//**************************************************************************

/// permissions that the certificate holder has
///
/// This structure represents the permissions that the certificate
/// holder has with respect to activities for a single application area,
/// identified by a Psid.
///
/// Note: The determination as to whether the activities are consistent with
/// the permissions indicated by the PSID and `ServiceSpecificPermissions` is
/// made by the SDEE and not by the SDS; the SDS provides the PSID and SSP
/// information to the SDEE to enable the SDEE to make that determination.
/// See 5.2.4.3.3 for more information.
///
/// Note: The SDEE specification is expected to specify what application
/// activities are permitted by particular `ServiceSpecificPermissions` values.
/// The SDEE specification is also expected EITHER to specify application
/// activities that are permitted if the `ServiceSpecificPermissions` is
/// omitted, OR to state that the `ServiceSpecificPermissions` need to always be
/// present.
///
/// Note: Consistency with signed SPDU: As noted in 5.1.1,
/// consistency between the SSP and the signed SPDU is defined by rules
/// specific to the given PSID and is out of scope for this standard.
///
/// Note: Consistency with issuing certificate: If a certificate has an
/// appPermissions entry A for which the ssp field is omitted, A is consistent
/// with the issuing certificate if the issuing certificate contains a
/// `PsidSspRange` P for which the following holds:
///   - The psid field in P is equal to the psid field in A and one of the following is true:
///     - The sspRange field in P indicates all.
///     - The sspRange field in P indicates opaque and one of the entries in opaque is an OCTET STRING of length 0.
///
/// For consistency rules for other forms of the ssp field, see the following subclauses.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct PsidSsp<'input> {
    pub psid: Psid,
    #[cfg_attr(feature = "serde", serde(borrow))]
    pub ssp: Option<ServiceSpecificPermissions<'input>>,
}

/// certificate issuing or requesting permissions of the certificate holder
///
/// This structure represents the certificate issuing or requesting
/// permissions of the certificate holder with respect to one particular set
/// of application permissions.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct PsidSspRange<'input> {
    /// identifies the application area
    pub psid: Psid,

    /// identifies the SSPs associated with that PSID for which
    /// the holder may issue or request certificates. If sspRange is omitted, the
    /// holder may issue or request certificates for any SSP for that PSID.
    #[cfg_attr(feature = "serde", serde(borrow))]
    pub ssp_range: Option<SspRange<'input>>,
}

/// public encryption key and the associated symmetric algorithm
///
/// This structure specifies a public encryption key and the associated
/// symmetric algorithm which is used for bulk data encryption when encrypting
/// for that public key.
///
/// Note: Canonicalization: This data structure is subject to canonicalization
/// for the relevant operations specified in 6.1.2 if it appears in a
/// `HeaderInfo` or in a `ToBeSignedCertificate`. The canonicalization applies to
/// the `BasePublicEncryptionKey`. See the definitions of `HeaderInfo` and
/// `ToBeSignedCertificate` for a specification of the canonicalization
/// operations.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct PublicEncryptionKey<'input> {
    pub supported_symm_alg: SymmAlgorithm,
    #[cfg_attr(feature = "serde", serde(borrow))]
    pub public_key: BasePublicEncryptionKey<'input>,
}

/// represents a public key and states with what algorithm the public key is to be used
///
/// Cryptographic mechanisms are defined in 5.3.
/// An `EccP256CurvePoint` or `EccP384CurvePoint` within a `PublicVerificationKey`
/// structure is invalid if it indicates the choice x-only.
///
/// Note: Critical information fields: If present, this is a critical
/// information field as defined in 5.2.6. An implementation that does not
/// recognize the indicated CHOICE when verifying a signed SPDU shall indicate
/// that the signed SPDU is invalid indicate that the signed SPDU is invalid
/// in the sense of 4.2.2.3.2, that is, it is invalid in the sense that its
/// validity cannot be established.
///
/// Note: Canonicalization: This data structure is subject to canonicalization
/// for the relevant operations specified in 6.1.2. The canonicalization
/// applies to the `EccP256CurvePoint` and the `Ecc384CurvePoint`. Both forms of
/// point are encoded in compressed form, i.e., such that the choice indicated
/// within the Ecc*`CurvePoint` is compressed-y-0 or compressed-y-1.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum PublicVerificationKey<'input> {
    #[cfg_attr(feature = "serde", serde(borrow))]
    EcdsaNistP256(EccP256CurvePoint<'input>),
    #[cfg_attr(feature = "serde", serde(borrow))]
    EcdsaBrainpoolP256r1(EccP256CurvePoint<'input>),
    #[cfg_attr(feature = "serde", serde(borrow))]
    EcdsaBrainpoolP384r1(EccP384CurvePoint<'input>),
    #[cfg_attr(feature = "serde", serde(borrow))]
    EcdsaNistP384(EccP384CurvePoint<'input>),
    #[cfg_attr(feature = "serde", serde(borrow))]
    EcsigSm2(EccP256CurvePoint<'input>),
}

/// Specifies a rectangle on the surface of the WGS84 ellipsoid
///
/// Specifies a rectangle on the surface of the WGS84 ellipsoid where the
/// sides are given by lines of constant latitude or longitude.
///
/// A point which contains an elevation component is considered to be within the rectangular region
/// if its horizontal projection onto the reference ellipsoid lies within the region.
///
/// A `RectangularRegion` is invalid if the northWest value is south of the southEast value, or if the
/// latitude values in the two points are equal, or if the longitude values in the two points are
/// equal; otherwise it is valid. A certificate that contains an invalid `RectangularRegion` is invalid.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct RectangularRegion {
    /// is the north-west corner of the rectangle.
    pub north_west: TwoDLocation,
    /// @param southEast is the south-east corner of the rectangle
    pub south_east: TwoDLocation,
}

/// Region and sub-regions
///
/// The meanings of the fields in this structure are to be interpreted
/// in the context of a country within which the region is located, referred
/// to as the "enclosing country". If this structure is used in a
/// `CountryAndSubregions` structure, the enclosing country is the one indicated
/// by the country field in the `CountryAndSubregions` structure. If other uses
/// are defined for this structure in future, it is expected that that
/// definition will include a specification of how the enclosing country can
/// be determined.
///
/// If the enclosing country is the United States of America:
/// - The region field identifies the state or statistically equivalent
///   entity using the integer version of the 2010 FIPS codes as provided by the
///   U.S. Census Bureau (see normative references in Clause 0).
/// - The values in the subregions field identify the county or county
///   equivalent entity using the integer version of the 2010 FIPS codes as
///   provided by the U.S. Census Bureau.
///
/// If the enclosing country is a different country from the USA, the meaning
/// of regionAndSubregions is not defined in this version of this standard.
/// A conformant implementation that implements this type shall recognize (in
/// the sense of "be able to determine whether a two-dimensional location lies
/// inside or outside the borders identified by"), for at least one enclosing
/// country, at least one value for a region within that country and at least
/// one subregion for the indicated region. In this version of this standard,
/// the only means to satisfy this is for a conformant implementation to
/// recognize, for the USA, at least one of the FIPS state codes for US
/// states, and at least one of the county codes in at least one of the
/// recognized states. The Protocol Implementation Conformance Statement
/// (PICS) provided in Annex A allows an implementation to state which
/// `UnCountryId` values it recognizes and which region values are recognized
/// within that country.
///
/// If a verifying implementation is required to check that an relevant
/// geographic information in a signed SPDU is consistent with a certificate
/// containing one or more instances of this type, then the SDS is permitted
/// to indicate that the signed SPDU is valid even if some values within
/// subregions are unrecognized in the sense defined above, so long as the
/// recognized instances of this type completely contain the relevant
/// geographic information. Informally, if the recognized values in the
/// certificate allow the SDS to determine that the SPDU is valid, then it
/// can make that determination even if there are also unrecognized values
/// in the certificate. This field is therefore not not a "critical
/// information field" as defined in 5.2.6, because unrecognized values are
/// permitted so long as the validity of the SPDU can be established with the
/// recognized values. However, as discussed in 5.2.6, the presence of an
/// unrecognized value in a certificate can make it impossible to determine
/// whether the certificate is valid and so whether the SPDU is valid.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct RegionAndSubregions {
    /// identifies a region within a country
    pub region: Uint8,

    /// identifies one or more subregions within region. A
    /// conformant implementation that supports `RegionAndSubregions` shall support
    /// a subregions field containing at least eight entries.
    pub subregions: SequenceOfUint16,
}

/// used for clarity of definitions
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SequenceOfHashedId3<'input>(
    #[cfg_attr(feature = "serde", serde(borrow))] pub Vec<HashedId3<'input>>,
);

/// used for clarity of definitions
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SequenceOfIdentifiedRegion(pub Vec<IdentifiedRegion>);

/// used for clarity of definitions
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SequenceOfLinkageSeed<'input>(
    #[cfg_attr(feature = "serde", serde(borrow))] pub Vec<LinkageSeed<'input>>,
);

/// used for clarity of definitions
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SequenceOfOctetString<'input>(
    #[cfg_attr(feature = "serde", serde(borrow))] pub Vec<&'input [u8]>,
);

/// used for clarity of definitions
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SequenceOfPsid(pub Vec<Psid>);

/// used for clarity of definitions
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SequenceOfPsidSsp<'input>(
    #[cfg_attr(feature = "serde", serde(borrow))] pub Vec<PsidSsp<'input>>,
);

/// used for clarity of definitions
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SequenceOfPsidSspRange<'input>(
    #[cfg_attr(feature = "serde", serde(borrow))] pub Vec<PsidSspRange<'input>>,
);

/// used for clarity of definitions
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SequenceOfRectangularRegion(pub Vec<RectangularRegion>);

/// used for clarity of definitions
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SequenceOfRegionAndSubregions(pub Vec<RegionAndSubregions>);

/// used for clarity of definitions
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SequenceOfUint16(pub Vec<Uint16>);

/// used for clarity of definitions
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SequenceOfUint8(pub Vec<Uint8>);

/// SSPs for a given entry in a `PsidSsp`
///
/// This structure represents the Service Specific Permissions (SSP)
/// relevant to a given entry in a `PsidSsp`. The meaning of the SSP is specific
/// to the associated Psid. SSPs may be PSID-specific octet strings or
/// bitmap-based. See Annex C for further discussion of how application
/// specifiers may choose which SSP form to use.
///
/// Note: Consistency with issuing certificate: If a certificate has an
/// appPermissions entry A for which the ssp field is opaque, A is consistent
/// with the issuing certificate if the issuing certificate contains one of
/// the following:
///   - (OPTION 1) A `SubjectPermissions` field indicating the choice all and no `PsidSspRange` field containing the psid field in A;
///   - (OPTION 2) A `PsidSspRange` P for which the following holds:
///     - The psid field in P is equal to the psid field in A and one of the following is true:
///       - The sspRange field in P indicates all.
///       - The sspRange field in P indicates opaque and one of the entries in the opaque field in P is an OCTET STRING identical to the opaque field in A.
///
/// For consistency rules for other types of `ServiceSpecificPermissions`, see the following subclauses.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum ServiceSpecificPermissions<'input> {
    #[cfg_attr(feature = "serde", serde(borrow))]
    Opaque(&'input [u8]),
    BitmapSsp(BitmapSsp<'input>),
}

//**************************************************************************
//                            Crypto Structures
//**************************************************************************

/// represents a signature for a supported public key algorithm
///
/// It may be contained within `SignedData` or Certificate.
///
/// Note: Critical information fields: If present, this is a critical
/// information field as defined in 5.2.5. An implementation that does not
/// recognize the indicated CHOICE for this type when verifying a signed SPDU
/// shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2,
/// that is, it is invalid in the sense that its validity cannot be
/// established.
///
/// Note: Canonicalization: This data structure is subject to canonicalization
/// for the relevant operations specified in 6.1.2. The canonicalization
/// applies to instances of this data structure of form `EcdsaP256Signature`
/// and `EcdsaP384Signature`.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum Signature<'input> {
    #[cfg_attr(feature = "serde", serde(borrow))]
    EcdsaNistP256Signature(EcdsaP256Signature<'input>),
    #[cfg_attr(feature = "serde", serde(borrow))]
    EcdsaBrainpoolP256r1Signature(EcdsaP256Signature<'input>),
    #[cfg_attr(feature = "serde", serde(borrow))]
    EcdsaBrainpoolP384r1Signature(EcdsaP384Signature<'input>),
    #[cfg_attr(feature = "serde", serde(borrow))]
    EcdsaNistP384Signature(EcdsaP384Signature<'input>),
    #[cfg_attr(feature = "serde", serde(borrow))]
    Sm2Signature(EcsigP256Signature<'input>),
}

/// identifies the SSPs associated with a PSID for which the holder may issue or request certificates
///
/// Note: Consistency with issuing certificate: If a certificate has a
/// `PsidSspRange` A for which the ssp field is opaque, A is consistent with
/// the issuing certificate if the issuing certificate contains one of the
/// following:
///   - (OPTION 1) A `SubjectPermissions` field indicating the choice all and no `PsidSspRange` field containing the psid field in A;
///   - (OPTION 2) A `PsidSspRange` P for which the following holds:
///     - The psid field in P is equal to the psid field in A and one of the following is true:
///       - The sspRange field in P indicates all.
///       - The sspRange field in P indicates opaque, and the sspRange field in
///         A indicates opaque, and every OCTET STRING within the opaque in A is a
///         duplicate of an OCTET STRING within the opaque in P.
///
/// If a certificate has a `PsidSspRange` A for which the ssp field is all,
/// A is consistent with the issuing certificate if the issuing certificate
/// contains a `PsidSspRange` P for which the following holds:
///   - (OPTION 1) A `SubjectPermissions` field indicating the choice all and no `PsidSspRange` field containing the psid field in A;
///   - (OPTION 2) A `PsidSspRange` P for which the psid field in P is equal to the psid field in A and the sspRange field in P indicates all.
///
/// For consistency rules for other types of `SspRange`, see the following subclauses.
///
/// Note: The choice "all" may also be indicated by omitting the
/// `SspRange` in the enclosing `PsidSspRange` structure. Omitting the `SspRange` is
/// preferred to explicitly indicating "all".
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum SspRange<'input> {
    #[cfg_attr(feature = "serde", serde(borrow))]
    Opaque(SequenceOfOctetString<'input>),
    All(()),
    #[cfg_attr(feature = "serde", serde(borrow))]
    BitmapSspRange(BitmapSspRange<'input>),
}

//**************************************************************************
//                          Certificate Components
//**************************************************************************

/// certificate holder's assurance level
///
/// This field contains the certificate holder's assurance level, which
/// indicates the security of both the platform and storage of secret keys as
/// well as the confidence in this assessment.
///
/// This field is encoded as defined in Table 1, where "A" denotes bit
/// fields specifying an assurance level, "R" reserved bit fields, and "C" bit
/// fields specifying the confidence.
///
/// Table 1: Bitwise encoding of subject assurance
/// | Bit number     |  7  |  6  |  5  |  4  |  3  |  2  |  1  |  0  |
/// | -------------- | --- | --- | --- | --- | --- | --- | --- | --- |
/// | Interpretation |  A  |  A  |  A  |  R  |  R  |  R  |  C  |  C  |
///
/// In Table 1, bit number 0 denotes the least significant bit. Bit 7
/// to bit 5 denote the device's assurance levels, bit 4 to bit 2 are reserved
/// for future use, and bit 1 and bit 0 denote the confidence.
///
/// The specification of these assurance levels as well as the
/// encoding of the confidence levels is outside the scope of the present
/// standard. It can be assumed that a higher assurance value indicates that
/// the holder is more trusted than the holder of a certificate with lower
/// assurance value and the same confidence value.
///
/// Note: This field was originally specified in ETSI TS 103 097 and
/// future uses of this field are anticipated to be consistent with future
/// versions of that standard.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SubjectAssurance<'input>(#[cfg_attr(feature = "serde", serde(borrow))] pub &'input [u8]);

/// This enumerated value indicates supported symmetric algorithms
///
/// The algorithm identifier identifies both the algorithm itself and a specific
/// mode of operation. The symmetric algorithms supported in this version of
/// this standard are AES-128 and SM4. The only mode of operation supported is
/// Counter Mode Encryption With Cipher Block Chaining Message Authentication
/// Code (CCM). Full details are given in 5.3.8.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum SymmAlgorithm {
    Aes128Ccm = 0,
    Sm4Ccm = 1,
}

impl TryFrom<i128> for SymmAlgorithm {
    type Error = ();

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SymmAlgorithm::Aes128Ccm),
            1 => Ok(SymmAlgorithm::Sm4Ccm),
            _ => Err(()),
        }
    }
}

/// provides the key bytes for use with an identified symmetric algorithm
///
/// The supported symmetric algorithms are AES-128 and SM4 in CCM mode as
/// specified in 5.3.8.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum SymmetricEncryptionKey<'input> {
    #[cfg_attr(feature = "serde", serde(borrow))]
    Aes128Ccm(&'input [u8]),
    #[cfg_attr(feature = "serde", serde(borrow))]
    Sm4Ccm(&'input [u8]),
}

/// contains an estimate of 3D location
///
/// The details of the structure are given in the definitions of the individual
/// fields below.
///
/// Note: The units used in this data structure are consistent with the
/// location data structures used in SAE J2735 \[B26\], though the encoding is
/// incompatible.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ThreeDLocation {
    pub latitude: Latitude,
    pub longitude: Longitude,
    pub elevation: Elevation,
}

/// is used to define validity regions for use in certificates
///
/// The latitude and longitude fields contain the latitude and
/// longitude as defined above.
///
/// Note: This data structure is consistent with the location encoding
/// used in SAE J2735, except that values 900 000 001 for latitude (used to
/// indicate that the latitude was not available) and 1 800 000 001 for
/// longitude (used to indicate that the longitude was not available) are not
/// valid.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct TwoDLocation {
    pub latitude: Latitude,
    pub longitude: Longitude,
}

//**************************************************************************
//                             Time Structures
//**************************************************************************

/// The number of (TAI) seconds since 00:00:00 UTC, 1 January, 2004
pub type Time32 = Uint32;

/// Estimate of the number of (TAI) microseconds since 00:00:00 UTC, 1 January, 2004
pub type Time64 = Uint64;

/// gives the validity period of a certificate
///
/// The start of the validity period is given by start and the end is given by
/// start + duration.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ValidityPeriod {
    pub start: Time32,
    pub duration: Duration,
}

//**************************************************************************
//                               Integer Types
//**************************************************************************

/// This atomic type is used in the definition of other data structures
///
/// It is for non-negative integers up to 65,535, i.e., (hex)ff ff.
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Uint16(pub u16);

/// This atomic type is used in the definition of other data structures
///
/// It is for non-negative integers up to 7, i.e., (hex)07.
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Uint3(pub u8);

/// This atomic type is used in the definition of other data structures
///
/// It is for non-negative integers up to 4,294,967,295, i.e.,
/// (hex)ff ff ff ff.
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Uint32(pub u32);

/// This atomic type is used in the definition of other data structures
///
/// It is for non-negative integers up to 18,446,744,073,709,551,615, i.e.,
/// (hex)ff ff ff ff ff ff ff ff.
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Uint64(pub u64);

/// This atomic type is used in the definition of other data structures
///
/// It is for non-negative integers up to 255, i.e., (hex)ff.
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Uint8(pub u8);

/// A UN country ID
///
/// This type contains the integer representation of the country or
/// area identifier as defined by the United Nations Statistics Division in
/// October 2013 (see normative references in Clause 0).
///
/// A conformant implementation that implements `IdentifiedRegion` shall
/// recognize (in the sense of be able to determine whether a two dimensional
/// location lies inside or outside the borders identified by) at least one
/// value of `UnCountryId`. The Protocol Implementation Conformance Statement
/// (PICS) provided in Annex A allows an implementation to state which
/// `UnCountryId` values it recognizes.
///
/// Since 2013 and before the publication of this version of this standard,
/// three changes have been made to the country code list, to define the
/// region "sub-Saharan Africa" and remove the "developed regions", and
/// "developing regions". A conformant implementation may recognize these
/// region identifiers in the sense defined in the previous paragraph.
/// If a verifying implementation is required to check that relevant
/// geographic information in a signed SPDU is consistent with a certificate
/// containing one or more instances of this type, then the SDS is permitted
/// to indicate that the signed SPDU is valid even if some instances of this
/// type are unrecognized in the sense defined above, so long as the
/// recognized instances of this type completely contain the relevant
/// geographic information. Informally, if the recognized values in the
/// certificate allow the SDS to determine that the SPDU is valid, then it
/// can make that determination even if there are also unrecognized values in
/// the certificate. This field is therefore not a "critical information
/// field" as defined in 5.2.6, because unrecognized values are permitted so
/// long as the validity of the SPDU can be established with the recognized
/// values. However, as discussed in 5.2.6, the presence of an unrecognized
/// value in a certificate can make it impossible to determine whether the
/// certificate and the SPDU are valid.
pub type UnCountryId = Uint16;

/// The value 900,000,001 indicates that the latitude was not available to the sender
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct UnknownLatitude(pub NinetyDegreeInt);

/// The value 1,800,000,001 indicates that the longitude was not available to the sender
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct UnknownLongitude(pub OneEightyDegreeInt);

//**************************************************************************
//                              Bit Field Types
//**************************************************************************

/// Fixed size, non-extensible BIT STRING
#[derive(Debug, Clone, PartialEq)]
pub struct BitString<const SIZE: usize>(pub [bool; SIZE]);

impl<const SIZE: usize> Default for BitString<SIZE> {
    fn default() -> Self {
        Self([false; SIZE])
    }
}

#[cfg(feature = "serde")]
impl<const SIZE: usize> Serialize for BitString<SIZE> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut seq = serializer.serialize_tuple(self.0.len())?;
        for elem in &self.0 {
            use serde::ser::SerializeTuple;

            seq.serialize_element(elem)?;
        }
        seq.end()
    }
}

impl<const SIZE: usize> From<Vec<bool>> for BitString<SIZE> {
    fn from(value: Vec<bool>) -> Self {
        let mut res = Self::default();
        let input_size = value.len();

        for (idx, item) in value.iter().enumerate().take(SIZE.min(input_size)) {
            res.0[idx] = *item;
        }

        res
    }
}

impl<const SIZE: usize> From<[bool; SIZE]> for BitString<SIZE> {
    fn from(value: [bool; SIZE]) -> Self {
        Self(value)
    }
}

//**************************************************************************
//                                  Tests
//**************************************************************************
