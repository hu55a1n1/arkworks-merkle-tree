use ark_crypto_primitives::{crh::{poseidon::{constraints::{CRHGadget as PoseidonCRHGadget, TwoToOneCRHGadget as PoseidonTwoToOneCRHGadget}, TwoToOneCRH as PoseidonTwoToOneCRH, CRH as PoseidonCRH}}, merkle_tree::{constraints::PathVar, MerkleTree, Path}};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::merkle_tree::constraints::ConfigGadget;
use ark_crypto_primitives::merkle_tree::{Config, IdentityDigestConverter};
use decaf377::Fq;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::eq::EqGadget;
use ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar;

pub struct Poseidon377MerkleTreeParams;
pub type Leaf = [Fq];
pub type LeafHash = PoseidonCRH<Fq>;
pub type TwoToOneHash = PoseidonTwoToOneCRH<Fq>;
pub type LeafDigest = <LeafHash as CRHScheme>::Output;
pub type InnerDigest = <TwoToOneHash as TwoToOneCRHScheme>::Output;
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
pub type LeafVar = [FpVar<Fq>];
pub type LeafDigestVar = <PoseidonCRHGadget<Fq> as CRHSchemeGadget<LeafHash, Fq>>::OutputVar;
pub type InnerDigestVar = <PoseidonTwoToOneCRHGadget<Fq> as TwoToOneCRHSchemeGadget<TwoToOneHash, Fq>>::OutputVar;
pub type LeafInnerDigestVarConverter = IdentityDigestConverter<FpVar<Fq>>;

pub struct Poseidon377MerkleTreeParamsVar;

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
pub type LeafHashParamsVar = <PoseidonCRHGadget<Fq> as CRHSchemeGadget<LeafHash, Fq>>::OutputVar;
pub type TwoToOneHashParams = <TwoToOneHash as TwoToOneCRHScheme>::Parameters;
pub type TwoToOneHashParamsVar = <PoseidonTwoToOneCRHGadget<Fq> as TwoToOneCRHSchemeGadget<TwoToOneHash, Fq>>::ParametersVar;

pub type Root = InnerDigest;
pub type RootVar = InnerDigestVar;

pub struct MerkleTreeVerification {
    // These are constants that will be embedded into the circuit
    pub leaf_crh_params: LeafHashParams,
    pub two_to_one_crh_params: TwoToOneHashParams,

    // These are the public inputs to the circuit.
    pub root: Root,
    pub leaf: Fq, // TODO: change to u8 along with `Leaf`

    // This is the private witness to the circuit.
    pub authentication_path: Option<Poseidon377MerklePath>,
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


#[cfg(test)]
mod test {
    use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
    use ark_std::rand::RngCore; // Needed to generate mds and ark

    use super::*;

    #[test]
    fn merkle_tree_constraints_correctness() {
        use ark_relations::r1cs::ConstraintSystem;

        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let (mds, ark) = {
            let mut test_rng = ark_std::test_rng();

            let mut mds = vec![vec![]; 3];
            for i in 0..3 {
                for _ in 0..3 {
                    mds[i].push(Fq::from(test_rng.next_u64()));
                }
            }
    
            let mut ark = vec![vec![]; 8 + 24];
            for i in 0..8 + 24 {
                for _ in 0..3 {
                    ark[i].push(Fq::from(test_rng.next_u64()));
                }
            }

            (mds, ark)
        };

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = PoseidonConfig::<Fq>::new(8, 24, 31, mds.clone(), ark.clone(), 2, 1);
        let two_to_one_crh_params = PoseidonConfig::<Fq>::new(8, 24, 31, mds, ark, 2, 1);

        // TODO: remove when `Leaf` is redefined to u8
        // Convert u8 values to Fq
        let leaves: Vec<[Fq; 1]> = [1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8]
            .iter()
            .map(|&u| [Fq::from(u as u64)])
            .collect();

        // Next, let's construct our tree.
        // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
        let tree = Poseidon377MerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
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
            leaf_crh_params,
            two_to_one_crh_params,

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