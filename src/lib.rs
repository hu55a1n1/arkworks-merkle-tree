pub mod poseidontree;

use ark_crypto_primitives::crh::{
    pedersen::{
        constraints::{
            CRHGadget as PedersenCRHGadget, TwoToOneCRHGadget as PedersenTwoToOneCRHGadget,
        },
        TwoToOneCRH as PedersenTwoToOneCRH, Window, CRH as PedersenCRH,
    },
    CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
};
use ark_crypto_primitives::merkle_tree::{
    constraints::{BytesVarDigestConverter, ConfigGadget, PathVar},
    ByteDigestConverter, Config, MerkleTree, Path,
};
use ark_ed_on_bls12_377::{constraints::EdwardsVar, EdwardsProjective, Fq};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};

#[derive(Clone)]
struct Window4x256;
impl Window for Window4x256 {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

type LeafHash = PedersenCRH<EdwardsProjective, Window4x256>;
type LeafHashGadget = PedersenCRHGadget<EdwardsProjective, EdwardsVar, Window4x256>;
type LeafHashParams = <LeafHash as CRHScheme>::Parameters;
type LeafHashParamsVar = <LeafHashGadget as CRHSchemeGadget<LeafHash, Fq>>::ParametersVar;
type CompressHash = PedersenTwoToOneCRH<EdwardsProjective, Window4x256>;
type CompressHashGadget = PedersenTwoToOneCRHGadget<EdwardsProjective, EdwardsVar, Window4x256>;
type CompressHashParams = <CompressHash as TwoToOneCRHScheme>::Parameters;
type CompressHashParamsVar =
    <CompressHashGadget as TwoToOneCRHSchemeGadget<CompressHash, Fq>>::ParametersVar;
type LeafDigest = <LeafHash as CRHScheme>::Output;
type LeafDigestVar = <LeafHashGadget as CRHSchemeGadget<LeafHash, Fq>>::OutputVar;
type InnerDigest = <CompressHash as TwoToOneCRHScheme>::Output;
type InnerDigestVar = <CompressHashGadget as TwoToOneCRHSchemeGadget<CompressHash, Fq>>::OutputVar;
type Leaf = [u8];
type LeafVar = [UInt8<Fq>];
type Root = InnerDigest;
type RootVar = InnerDigestVar;

struct Pedersen377MerkleTreeParams;

impl Config for Pedersen377MerkleTreeParams {
    type Leaf = Leaf;
    type LeafDigest = LeafDigest;
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
    type InnerDigest = InnerDigest;
    type LeafHash = LeafHash;
    type TwoToOneHash = CompressHash;
}

struct Pedersen377MerkleTreeParamsVar;
impl ConfigGadget<Pedersen377MerkleTreeParams, Fq> for Pedersen377MerkleTreeParamsVar {
    type Leaf = LeafVar;
    type LeafDigest = LeafDigestVar;
    type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, Fq>;
    type InnerDigest = InnerDigestVar;
    type LeafHash = LeafHashGadget;
    type TwoToOneHash = CompressHashGadget;
}

type Pedersen377MerkleTree = MerkleTree<Pedersen377MerkleTreeParams>;
type Pedersen377MerklePath = Path<Pedersen377MerkleTreeParams>;
type Pedersen377MerklePathVar =
    PathVar<Pedersen377MerkleTreeParams, Fq, Pedersen377MerkleTreeParamsVar>;

struct MerkleTreeVerification {
    // These are constants that will be embedded into the circuit
    leaf_crh_params: LeafHashParams,
    two_to_one_crh_params: CompressHashParams,

    // These are the public inputs to the circuit.
    root: Root,
    leaf: u8,

    // This is the private witness to the circuit.
    authentication_path: Option<Pedersen377MerklePath>,
}

impl ConstraintSynthesizer<Fq> for MerkleTreeVerification {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
        // First, we allocate the public inputs
        let root =
            <RootVar as AllocVar<Root, Fq>>::new_input(ark_relations::ns!(cs, "root_var"), || {
                Ok(&self.root)
            })?;

        let leaf = UInt8::new_input(ark_relations::ns!(cs, "leaf_var"), || Ok(&self.leaf))?;

        // Then, we allocate the public parameters as constants:
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            CompressHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // Finally, we allocate our path as a private witness variable:
        let path =
            Pedersen377MerklePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
                Ok(self.authentication_path.as_ref().unwrap())
            })?;

        let is_member =
            path.verify_membership(&leaf_crh_params, &two_to_one_crh_params, &root, &[leaf])?;
        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::pairing::Pairing;
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng, UniformRand,
    };

    use super::*;

    fn test_prove_and_verify<E>(n_iters: usize)
    where
        E: Pairing,
    {
        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let mut rng = test_rng();

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <CompressHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        // Next, let's construct our tree.
        // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
        let tree = Pedersen377MerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            [1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8].map(|u| [u]), // the i-th entry is the i-th leaf.
        )
        .unwrap();

        // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
        let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!
                                                     // This should be a proof for the membership of a leaf with value 9. Let's check that!

        // First, let's get the root we want to verify against:
        let root = tree.root();

        let circuit = MerkleTreeVerification {
            // constants
            leaf_crh_params: leaf_crh_params.clone(),
            two_to_one_crh_params: two_to_one_crh_params.clone(),

            // public inputs
            root,
            leaf: 9u8,

            // witness
            authentication_path: Some(proof),
        };

        let (pk, vk) = Groth16::<E>::circuit_specific_setup(
            MerkleTreeVerification {
                leaf_crh_params,
                two_to_one_crh_params,
                root,
                leaf: 0,
                authentication_path: None,
            },
            &mut rng,
        )
        .unwrap();
        let pvk = prepare_verifying_key::<E>(&vk);

        let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[], &proof).unwrap());
    }

    #[test]
    fn merkle_tree_constraints_correctness() {
        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let mut rng = test_rng();

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <CompressHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        // Next, let's construct our tree.
        // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
        let tree = Pedersen377MerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            [1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8].map(|u| [u]), // the i-th entry is the i-th leaf.
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
            leaf: 9u8,

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

    // Run this test via `cargo test --release test_merkle_tree_constraints_soundness`.
    // This tests that a given invalid authentication path will fail.
    #[test]
    fn merkle_tree_constraints_soundness() {
        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let mut rng = test_rng();

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <CompressHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        // Next, let's construct our tree.
        // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
        let tree = Pedersen377MerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            [1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8].map(|u| [u]), // the i-th entry is the i-th leaf.
        )
        .unwrap();

        // We just mutate the first leaf
        let second_tree = Pedersen377MerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            [4u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8].map(|u| [u]), // the i-th entry is the i-th leaf.
        )
        .unwrap();

        // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
        let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!

        // But, let's get the root we want to verify against:
        let wrong_root = second_tree.root();

        let circuit = MerkleTreeVerification {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root: wrong_root,
            leaf: 9u8,

            // witness
            authentication_path: Some(proof),
        };

        // Next, let's make the constraint system!
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        // We expect this to fail!
        assert!(!is_satisfied);
    }

    /// Generate a merkle tree, its constraints, and test its constraints
    fn merkle_tree_test(
        leaves: Vec<Vec<u8>>,
        use_bad_root: bool,
        update_query: Option<(usize, Vec<u8>)>,
    ) -> () {
        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <CompressHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();
        let mut tree =
            Pedersen377MerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, leaves.clone())
                .unwrap();
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(
                    &leaf_crh_params,
                    &two_to_one_crh_params,
                    &root,
                    leaf.as_slice()
                )
                .unwrap());

            // Allocate Merkle Tree Root
            let root = <LeafHashGadget as CRHSchemeGadget<LeafHash, _>>::OutputVar::new_witness(
                ark_relations::ns!(cs, "new_digest"),
                || {
                    if use_bad_root {
                        Ok(<LeafHash as CRHScheme>::Output::default())
                    } else {
                        Ok(root)
                    }
                },
            )
            .unwrap();

            let constraints_from_digest = cs.num_constraints();
            println!("constraints from digest: {}", constraints_from_digest);

            // Allocate Parameters for CRH
            let leaf_crh_params_var =
                <LeafHashGadget as CRHSchemeGadget<LeafHash, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "leaf_crh_parameter"),
                    &leaf_crh_params,
                )
                .unwrap();
            let two_to_one_crh_params_var = <CompressHashGadget as TwoToOneCRHSchemeGadget<
                CompressHash,
                _,
            >>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "two_to_one_crh_parameter"),
                &two_to_one_crh_params,
            )
            .unwrap();

            let constraints_from_params = cs.num_constraints() - constraints_from_digest;
            println!("constraints from parameters: {}", constraints_from_params);

            // Allocate Leaf
            let leaf_g = UInt8::new_input_vec(cs.clone(), leaf).unwrap();

            let constraints_from_leaf =
                cs.num_constraints() - constraints_from_params - constraints_from_digest;
            println!("constraints from leaf: {}", constraints_from_leaf);

            // Allocate Merkle Tree Path
            let cw: PathVar<Pedersen377MerkleTreeParams, Fq, Pedersen377MerkleTreeParamsVar> =
                PathVar::new_witness(ark_relations::ns!(cs, "new_witness"), || Ok(&proof)).unwrap();

            let constraints_from_path = cs.num_constraints()
                - constraints_from_params
                - constraints_from_digest
                - constraints_from_leaf;
            println!("constraints from path: {}", constraints_from_path);

            assert!(cs.is_satisfied().unwrap());
            assert!(cw
                .verify_membership(
                    &leaf_crh_params_var,
                    &two_to_one_crh_params_var,
                    &root,
                    &leaf_g,
                )
                .unwrap()
                .value()
                .unwrap());
            let setup_constraints = constraints_from_leaf
                + constraints_from_digest
                + constraints_from_params
                + constraints_from_path;
            println!(
                "number of constraints: {}",
                cs.num_constraints() - setup_constraints
            );

            assert!(
                cs.is_satisfied().unwrap(),
                "verification constraints not satisfied"
            );
        }

        // check update
        if let Some(update_query) = update_query {
            let cs = ConstraintSystem::<Fq>::new_ref();
            // allocate parameters for CRH
            let leaf_crh_params_var =
                <LeafHashGadget as CRHSchemeGadget<LeafHash, _>>::ParametersVar::new_constant(
                    ark_relations::ns!(cs, "leaf_crh_parameter"),
                    &leaf_crh_params,
                )
                .unwrap();
            let two_to_one_crh_params_var = <CompressHashGadget as TwoToOneCRHSchemeGadget<
                CompressHash,
                _,
            >>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "two_to_one_crh_parameter"),
                &two_to_one_crh_params,
            )
            .unwrap();

            // allocate old leaf and new leaf
            let old_leaf_var =
                UInt8::new_input_vec(ark_relations::ns!(cs, "old_leaf"), &leaves[update_query.0])
                    .unwrap();
            let new_leaf_var =
                UInt8::new_input_vec(ark_relations::ns!(cs, "new_leaf"), &update_query.1).unwrap();
            //
            // suppose the verifier already knows old root, new root, old leaf, new leaf, and the original path (so they are public)
            let old_root = tree.root();
            let old_root_var =
                <LeafHashGadget as CRHSchemeGadget<LeafHash, _>>::OutputVar::new_input(
                    ark_relations::ns!(cs, "old_root"),
                    || Ok(old_root),
                )
                .unwrap();
            let old_path = tree.generate_proof(update_query.0).unwrap();
            let old_path_var: PathVar<
                Pedersen377MerkleTreeParams,
                Fq,
                Pedersen377MerkleTreeParamsVar,
            > = PathVar::new_input(ark_relations::ns!(cs, "old_path"), || Ok(old_path)).unwrap();
            let new_root = {
                tree.update(update_query.0, &update_query.1).unwrap();
                tree.root()
            };
            let new_root_var =
                <LeafHashGadget as CRHSchemeGadget<LeafHash, _>>::OutputVar::new_input(
                    ark_relations::ns!(cs, "new_root"),
                    || Ok(new_root),
                )
                .unwrap();
            // verifier need to get a proof (the witness) to show the known new root is correct
            assert!(old_path_var
                .update_and_check(
                    &leaf_crh_params_var,
                    &two_to_one_crh_params_var,
                    &old_root_var,
                    &new_root_var,
                    &old_leaf_var,
                    &new_leaf_var,
                )
                .unwrap()
                .value()
                .unwrap());
            assert!(cs.is_satisfied().unwrap())
        }
    }

    #[test]
    fn good_root_test() {
        let mut leaves = Vec::new();
        for i in 0..4u8 {
            let input = vec![i; 30];
            leaves.push(input);
        }
        merkle_tree_test(leaves, false, Some((3usize, vec![7u8; 30])));
    }

    #[test]
    #[should_panic]
    fn bad_root_test() {
        let mut leaves = Vec::new();
        for i in 0..4u8 {
            let input = vec![i; 30];
            leaves.push(input);
        }
        merkle_tree_test(leaves, true, None);
    }
}
