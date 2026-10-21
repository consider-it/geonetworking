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

// impl<'payload> Ieee1609Dot2Data<'payload> {
//     /// retrieves unencrypted payload, if present
//     #[must_use]
//     pub fn data_payload(&self) -> Option<&'payload [u8]> {
//         match &self.content {
//             Ieee1609Dot2Content::UnsecuredData(p) => Some(p.0),
//             Ieee1609Dot2Content::SignedData(s) => s
//                 .tbs_data
//                 .payload
//                 .data
//                 .as_ref()
//                 .and_then(Ieee1609Dot2Data::data_payload),
//             _ => None,
//         }
//     }
// }

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

pub use rasn_its::ieee1609dot2::base_types::GeographicRegion;
pub use rasn_its::ieee1609dot2::base_types::GroupLinkageValue;
pub use rasn_its::ieee1609dot2::base_types::HashAlgorithm;

// impl TryFrom<i128> for HashAlgorithm {
//     type Error = ();

//     fn try_from(value: i128) -> Result<Self, Self::Error> {
//         match value {
//             0 => Ok(HashAlgorithm::Sha256),
//             1 => Ok(HashAlgorithm::Sha384),
//             2 => Ok(HashAlgorithm::Sm3),
//             _ => Err(()),
//         }
//     }
// }

pub use rasn_its::ieee1609dot2::base_types::HashedId10;
pub use rasn_its::ieee1609dot2::base_types::HashedId3;
pub use rasn_its::ieee1609dot2::base_types::HashedId32;
pub use rasn_its::ieee1609dot2::base_types::HashedId48;
pub use rasn_its::ieee1609dot2::base_types::HashedId8;
pub use rasn_its::ieee1609dot2::base_types::Hostname;

//**************************************************************************
//                             Pseudonym Linkage
//**************************************************************************

pub use rasn_its::ieee1609dot2::base_types::IValue;
pub use rasn_its::ieee1609dot2::base_types::IdentifiedRegion;
pub use rasn_its::ieee1609dot2::base_types::KnownLatitude;
pub use rasn_its::ieee1609dot2::base_types::KnownLongitude;
pub use rasn_its::ieee1609dot2::base_types::LaId;
pub use rasn_its::ieee1609dot2::base_types::Latitude;
pub use rasn_its::ieee1609dot2::base_types::LinkageSeed;
pub use rasn_its::ieee1609dot2::base_types::LinkageValue;
pub use rasn_its::ieee1609dot2::base_types::Longitude;
pub use rasn_its::ieee1609dot2::base_types::NinetyDegreeInt;
pub use rasn_its::ieee1609dot2::base_types::OneEightyDegreeInt;

//**************************************************************************
//                            OCTET STRING Types
//**************************************************************************

pub use rasn_its::ieee1609dot2::base_types::Opaque;
pub use rasn_its::ieee1609dot2::base_types::PolygonalRegion;
pub use rasn_its::ieee1609dot2::base_types::Psid;

//**************************************************************************
//                              PSID / ITS-AID
//**************************************************************************

pub use rasn_its::ieee1609dot2::base_types::PsidSsp;
pub use rasn_its::ieee1609dot2::base_types::PsidSspRange;
pub use rasn_its::ieee1609dot2::base_types::PublicEncryptionKey;
pub use rasn_its::ieee1609dot2::base_types::PublicVerificationKey;
pub use rasn_its::ieee1609dot2::base_types::RectangularRegion;
pub use rasn_its::ieee1609dot2::base_types::RegionAndSubregions;
pub use rasn_its::ieee1609dot2::base_types::SequenceOfHashedId3;
pub use rasn_its::ieee1609dot2::base_types::SequenceOfIdentifiedRegion;
pub use rasn_its::ieee1609dot2::base_types::SequenceOfLinkageSeed;
// pub use rasn_its::ieee1609dot2::base_types::SequenceOfOctetString;
pub use rasn_its::ieee1609dot2::base_types::SequenceOfPsid;
pub use rasn_its::ieee1609dot2::base_types::SequenceOfPsidSsp;
pub use rasn_its::ieee1609dot2::base_types::SequenceOfPsidSspRange;
pub use rasn_its::ieee1609dot2::base_types::SequenceOfRectangularRegion;
pub use rasn_its::ieee1609dot2::base_types::SequenceOfRegionAndSubregions;
pub use rasn_its::ieee1609dot2::base_types::SequenceOfUint16;
pub use rasn_its::ieee1609dot2::base_types::SequenceOfUint8;
pub use rasn_its::ieee1609dot2::base_types::ServiceSpecificPermissions;

//**************************************************************************
//                            Crypto Structures
//**************************************************************************

pub use rasn_its::ieee1609dot2::base_types::Signature;
pub use rasn_its::ieee1609dot2::base_types::SspRange;

//**************************************************************************
//                          Certificate Components
//**************************************************************************

pub use rasn_its::ieee1609dot2::base_types::SubjectAssurance;
pub use rasn_its::ieee1609dot2::base_types::SymmAlgorithm;

// impl TryFrom<i128> for SymmAlgorithm {
//     type Error = ();

//     fn try_from(value: i128) -> Result<Self, Self::Error> {
//         match value {
//             0 => Ok(SymmAlgorithm::Aes128Ccm),
//             1 => Ok(SymmAlgorithm::Sm4Ccm),
//             _ => Err(()),
//         }
//     }
// }

pub use rasn_its::ieee1609dot2::base_types::SymmetricEncryptionKey;
pub use rasn_its::ieee1609dot2::base_types::ThreeDLocation;
pub use rasn_its::ieee1609dot2::base_types::TwoDLocation;

//**************************************************************************
//                             Time Structures
//**************************************************************************

pub use rasn_its::ieee1609dot2::base_types::Time32;
pub use rasn_its::ieee1609dot2::base_types::Time64;
pub use rasn_its::ieee1609dot2::base_types::ValidityPeriod;

//**************************************************************************
//                               Integer Types
//**************************************************************************

pub use rasn_its::ieee1609dot2::base_types::Uint16;
pub use rasn_its::ieee1609dot2::base_types::Uint3;
pub use rasn_its::ieee1609dot2::base_types::Uint32;
pub use rasn_its::ieee1609dot2::base_types::Uint64;
pub use rasn_its::ieee1609dot2::base_types::Uint8;
pub use rasn_its::ieee1609dot2::base_types::UnCountryId;
pub use rasn_its::ieee1609dot2::base_types::UnknownLatitude;
pub use rasn_its::ieee1609dot2::base_types::UnknownLongitude;

//**************************************************************************
//                              Bit Field Types
//**************************************************************************

// pub use rasn_its::ieee1609dot2::base_types::BitString;

// impl<const SIZE: usize> Default for BitString<SIZE> {
//     fn default() -> Self {
//         Self([false; SIZE])
//     }
// }

// #[cfg(feature = "serde")]
// impl<const SIZE: usize> Serialize for BitString<SIZE> {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         use serde::ser::SerializeTuple;
//         let mut seq = serializer.serialize_tuple(self.0.len())?;
//         for elem in &self.0 {
//             use serde::ser::SerializeTuple;

//             seq.serialize_element(elem)?;
//         }
//         seq.end()
//     }
// }

// impl<const SIZE: usize> From<Vec<bool>> for BitString<SIZE> {
//     fn from(value: Vec<bool>) -> Self {
//         let mut res = Self::default();
//         let input_size = value.len();

//         for (idx, item) in value.iter().enumerate().take(SIZE.min(input_size)) {
//             res.0[idx] = *item;
//         }

//         res
//     }
// }

// impl<const SIZE: usize> From<[bool; SIZE]> for BitString<SIZE> {
//     fn from(value: [bool; SIZE]) -> Self {
//         Self(value)
//     }
// }

//**************************************************************************
//                                  Tests
//**************************************************************************
