#!/usr/bin/env bash
# Exports a YOLO-family detector to ONNX at ./models/detector.onnx.
#
# LICENCE WARNING: Ultralytics YOLOv8/YOLO11 code and weights are AGPL-3.0. Running them inside a
# commercial, network-served product requires either AGPL compliance or an Ultralytics Enterprise
# licence. For a permissively licensed alternative, export an Apache-2.0 model with a compatible
# single-output head (4 box + C class scores), or adapt detector.postprocess() to its output.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p models
MODEL="${1:-yolo11s.pt}"   # n = fastest, s = best accuracy/CPU trade-off for 500 cams
python3 -m venv .export-venv
.export-venv/bin/pip install -q ultralytics onnx onnxslim
.export-venv/bin/yolo export model="$MODEL" format=onnx imgsz=640 opset=17 simplify=True
mv "${MODEL%.pt}.onnx" models/detector.onnx
echo "Wrote models/detector.onnx"
