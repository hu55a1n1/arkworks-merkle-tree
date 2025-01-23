// use crate::crh::{CRHScheme, TwoToOneCRHScheme};
pub use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_crypto_primitives::{crh::{bowe_hopwood::constraints::ParametersVar, poseidon::{constraints::{CRHGadget as PoseidonCRHGadget, TwoToOneCRHGadget as PoseidonTwoToOneCRHGadget}, TwoToOneCRH as PoseidonTwoToOneCRH, CRH as PoseidonCRH}}, merkle_tree::{constraints::PathVar, MerkleTree, Path}};
use ark_crypto_primitives::crh::{CRHSchemeGadget, TwoToOneCRHSchemeGadget};
// reexport
pub use ark_crypto_primitives::crh::{TwoToOneCRHScheme, CRHScheme};
use ark_crypto_primitives::merkle_tree::constraints::ConfigGadget;
use ark_crypto_primitives::merkle_tree::{Config, IdentityDigestConverter};
// use ark_ed_on_bls12_377::{constraints::FqVar, Fq};
use decaf377::Fq;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::Boolean, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::eq::EqGadget;
use ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar;

pub struct Poseidon377MerkleTreeParams;

// TODO fix this
// type Leaf = [u8];
type Leaf = [Fq];

pub type LeafHash = PoseidonCRH<Fq>;
pub type TwoToOneHash = PoseidonTwoToOneCRH<Fq>;

type LeafDigest = <LeafHash as CRHScheme>::Output;
type InnerDigest = <TwoToOneHash as TwoToOneCRHScheme>::Output;
pub type LeafInnerDigestConverter = IdentityDigestConverter<Fq>;

impl Config for Poseidon377MerkleTreeParams {
    type Leaf = Leaf;
    type LeafDigest = LeafDigest;

    type LeafInnerDigestConverter = LeafInnerDigestConverter;
    type InnerDigest = InnerDigest;
    
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

// Define type aliases for the variable types
// type LeafVar = [UInt8<Fq>];
type LeafVar = [FpVar<Fq>];
type LeafDigestVar = <PoseidonCRHGadget<Fq> as CRHSchemeGadget<LeafHash, Fq>>::OutputVar;
type InnerDigestVar = <PoseidonTwoToOneCRHGadget<Fq> as TwoToOneCRHSchemeGadget<TwoToOneHash, Fq>>::OutputVar;
type LeafInnerDigestVarConverter = IdentityDigestConverter<FpVar<Fq>>;

struct Poseidon377MerkleTreeParamsVar;

impl ConfigGadget<Poseidon377MerkleTreeParams, Fq> for Poseidon377MerkleTreeParamsVar {
    type Leaf = LeafVar;
    type LeafDigest = LeafDigestVar;

    type LeafInnerConverter = LeafInnerDigestVarConverter;
    type InnerDigest = InnerDigestVar;

    type LeafHash = PoseidonCRHGadget<Fq>;
    type TwoToOneHash = PoseidonTwoToOneCRHGadget<Fq>;
}

pub type Poseidon377MerkleTree = MerkleTree<Poseidon377MerkleTreeParams>;
pub type Poseidon377MerklePath = Path<Poseidon377MerkleTreeParams>;
pub type Poseidon377MerklePathVar =
    PathVar<Poseidon377MerkleTreeParams, Fq, Poseidon377MerkleTreeParamsVar>;

pub type LeafHashParams = <LeafHash as CRHScheme>::Parameters;
type LeafHashParamsVar = <PoseidonCRHGadget<Fq> as CRHSchemeGadget<LeafHash, Fq>>::OutputVar;
pub type TwoToOneHashParams = <TwoToOneHash as TwoToOneCRHScheme>::Parameters;
type TwoToOneHashParamsVar = <PoseidonTwoToOneCRHGadget<Fq> as TwoToOneCRHSchemeGadget<TwoToOneHash, Fq>>::ParametersVar;

pub type Root = InnerDigest;
type RootVar = InnerDigestVar;

struct MerkleTreeVerification {
    // These are constants that will be embedded into the circuit
    leaf_crh_params: LeafHashParams,
    two_to_one_crh_params: TwoToOneHashParams,

    // These are the public inputs to the circuit.
    root: Root,
    leaf: Fq, // TODO: change to u8 along with `Leaf`

    // This is the private witness to the circuit.
    authentication_path: Option<Poseidon377MerklePath>,
}

impl ConstraintSynthesizer<Fq> for MerkleTreeVerification {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
        // First, we allocate the public inputs
        let root =
            <RootVar as AllocVar<Root, Fq>>::new_input(ark_relations::ns!(cs, "root_var"), || {
                Ok(&self.root)
            })?;

        // let leaf = UInt8::new_input(ark_relations::ns!(cs, "leaf_var"), || Ok(&self.leaf))?;
        let leaf = FpVar::<Fq>::new_input(ark_relations::ns!(cs, "leaf_var"), || Ok(&self.leaf))?;

        // Then, we allocate the public parameters as constants:
        let leaf_crh_params_var = CRHParametersVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params_var = CRHParametersVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // Finally, we allocate our path as a private witness variable:
        let path =
            Poseidon377MerklePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
                Ok(self.authentication_path.as_ref().unwrap())
            })?;

        let is_member =
            path.verify_membership(&leaf_crh_params_var, &two_to_one_crh_params_var, &root, &[leaf])?;
        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}


/// The const input for an [`SettlementProof`].
#[derive(Clone, Debug)]
pub struct SettlementProofConst {
    // Poseidon CRH constants that will be embedded into the circuit
    pub leaf_crh_params: LeafHashParams,
    pub two_to_one_crh_params: TwoToOneHashParams,
}

use poseidon377::{RATE_1_PARAMS, RATE_2_PARAMS};
use poseidon_parameters::v1::Matrix;

impl Default for SettlementProofConst {
    fn default() -> Self {
        // fixme: unsafe alpha conversion?
        let leaf_crh_params = {
            let params = RATE_1_PARAMS;
            PoseidonConfig::<Fq>::new(
                params.rounds.full(),
                params.rounds.partial(),
                u32::from_le_bytes(params.alpha.to_bytes_le()).into(),
                params.mds.0 .0.into_nested_vec(),
                params.arc.0.into_nested_vec(),
                1,
                1,
            )
        };
        let two_to_one_crh_params = {
            let params = RATE_2_PARAMS;
            PoseidonConfig::<Fq>::new(
                params.rounds.full(),
                params.rounds.partial(),
                u32::from_le_bytes(params.alpha.to_bytes_le()).into(),
                params.mds.0 .0.into_nested_vec(),
                params.arc.0.into_nested_vec(),
                2,
                1,
            )
        };
        Self {
            leaf_crh_params,
            two_to_one_crh_params,
        }
    }
}

pub trait MatrixExt {
    fn into_nested_vec(self) -> Vec<Vec<Fq>>;
}

impl<const N_ROWS: usize, const N_COLS: usize, const N_ELEMENTS: usize> MatrixExt
    for Matrix<N_ROWS, N_COLS, N_ELEMENTS>
{
    fn into_nested_vec(self) -> Vec<Vec<Fq>> {
        self.elements
            .chunks(N_COLS)
            .map(|row| row.to_vec())
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn merkle_tree_constraints_correctness() {
        use ark_relations::r1cs::ConstraintSystem;

        // First, let's sample the public parameters for the hash functions:
        let poseidon_constants = SettlementProofConst::default();

        // TODO: remove when `Leaf` is redefined to u8
        // Convert u8 values to Fq
        let leaves: Vec<[Fq; 1]> = [1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8]
            .iter()
            .map(|&u| [Fq::from(u as u64)])
            .collect();

        // Next, let's construct our tree.
        // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
        let tree = Poseidon377MerkleTree::new(
            &poseidon_constants.leaf_crh_params,
            &poseidon_constants.two_to_one_crh_params,
            // [1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8].map(|u| [u]), // the i-th entry is the i-th leaf.
            leaves,
        )
        .unwrap();

        // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
        let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!
                                                     // This should be a proof for the membership of a leaf with value 9. Let's check that!

        // First, let's get the root we want to verify against:
        let root = tree.root();

        let circuit = MerkleTreeVerification {
            // constants
            leaf_crh_params: poseidon_constants.leaf_crh_params,
            two_to_one_crh_params: poseidon_constants.two_to_one_crh_params,

            // public inputs
            root,
            leaf: Fq::from(9u8 as u64),

            // witness
            authentication_path: Some(proof),
        };

        // Next, let's make the circuit!
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        if !is_satisfied {
            // If it isn't, find out the offending constraint.
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(is_satisfied);
    }
}