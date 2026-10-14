#!/usr/bin/env bash
# Environment of test G1: SageMath from conda-forge and the lattice
# estimator at the commit used for the paper's estimates (53da598), inside
# WSL or any Linux.
#
#   bash scripts/setup_wsl_sage.sh [PREFIX]     (default PREFIX=$HOME/fairhe-sage)
#   $PREFIX/miniforge/envs/sage/bin/python scripts/security_v8.py --le $PREFIX/lattice-estimator
set -euo pipefail
PREFIX="${1:-$HOME/fairhe-sage}"
mkdir -p "$PREFIX"
if [ ! -x "$PREFIX/miniforge/bin/mamba" ]; then
  curl -fsSL -o "$PREFIX/miniforge.sh" \
    https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh
  bash "$PREFIX/miniforge.sh" -b -p "$PREFIX/miniforge"
fi
if [ ! -x "$PREFIX/miniforge/envs/sage/bin/sage" ]; then
  "$PREFIX/miniforge/bin/mamba" create -y -n sage sage
fi
if [ ! -d "$PREFIX/lattice-estimator/.git" ]; then
  git clone https://github.com/malb/lattice-estimator "$PREFIX/lattice-estimator"
fi
git -C "$PREFIX/lattice-estimator" checkout --quiet 53da598
"$PREFIX/miniforge/envs/sage/bin/sage" --version
echo "estimator at $(git -C "$PREFIX/lattice-estimator" rev-parse --short HEAD)"
