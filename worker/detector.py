"""CPU object detector: ONNX Runtime (OpenVINO EP when available) on YOLO-style exports.

Expects the common single-output head of shape (1, 4+C, N) with (cx, cy, w, h, class scores...),
as produced by YOLOv8/YOLO11 ONNX exports. Check the licence of the weights you deploy.
"""
import os

import cv2
import numpy as np

COCO = ["person", "bicycle", "car", "motorcycle", "airplane", "bus", "train", "truck", "boat", "traffic light",
        "fire hydrant", "stop sign", "parking meter", "bench", "bird", "cat", "dog", "horse", "sheep", "cow",
        "elephant", "bear", "zebra", "giraffe", "backpack", "umbrella", "handbag", "tie", "suitcase", "frisbee",
        "skis", "snowboard", "sports ball", "kite", "baseball bat", "baseball glove", "skateboard", "surfboard",
        "tennis racket", "bottle", "wine glass", "cup", "fork", "knife", "spoon", "bowl", "banana", "apple",
        "sandwich", "orange", "broccoli", "carrot", "hot dog", "pizza", "donut", "cake", "chair", "couch",
        "potted plant", "bed", "dining table", "toilet", "tv", "laptop", "mouse", "remote", "keyboard",
        "cell phone", "microwave", "oven", "toaster", "sink", "refrigerator", "book", "clock", "vase",
        "scissors", "teddy bear", "hair drier", "toothbrush"]

DEFAULT_CLASSES = "person,bicycle,car,motorcycle,bus,truck,dog,cat,backpack,handbag,suitcase,knife"


class Detector:
    def __init__(self, path: str, conf: float = 0.45, iou: float = 0.45, size: int = 640,
                 classes: str = DEFAULT_CLASSES, names: list[str] | None = None):
        import onnxruntime as ort
        so = ort.SessionOptions()
        so.intra_op_num_threads = int(os.environ.get("VMS_ORT_THREADS", "4"))
        so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        avail = ort.get_available_providers()
        providers = [p for p in ("OpenVINOExecutionProvider", "CPUExecutionProvider") if p in avail]
        self.sess = ort.InferenceSession(path, so, providers=providers)
        self.inp = self.sess.get_inputs()[0].name
        shape = self.sess.get_inputs()[0].shape
        self.size = shape[2] if isinstance(shape[2], int) else size
        self.conf, self.iou = conf, iou
        self.names = names or COCO
        self.keep = {self.names.index(c) for c in classes.split(",") if c in self.names}

    def preprocess(self, img: np.ndarray):
        h, w = img.shape[:2]
        r = min(self.size / h, self.size / w)
        nh, nw = int(round(h * r)), int(round(w * r))
        canvas = np.full((self.size, self.size, 3), 114, np.uint8)
        canvas[:nh, :nw] = cv2.resize(img, (nw, nh), interpolation=cv2.INTER_LINEAR)
        x = np.ascontiguousarray(canvas[:, :, ::-1].transpose(2, 0, 1)[None], dtype=np.float32) / 255.0
        return x, r

    def postprocess(self, out: np.ndarray, r: float, w: int, h: int):
        """out: (4+C, N). Returns [(x1,y1,x2,y2 normalised), conf, label]."""
        p = out.T
        scores = p[:, 4:]
        cls = scores.argmax(1)
        conf = scores[np.arange(len(scores)), cls]
        m = (conf >= self.conf) & np.isin(cls, list(self.keep))
        if not m.any():
            return []
        b, cls, conf = p[m, :4], cls[m], conf[m]
        x1 = np.clip((b[:, 0] - b[:, 2] / 2) / r, 0, w)
        y1 = np.clip((b[:, 1] - b[:, 3] / 2) / r, 0, h)
        x2 = np.clip((b[:, 0] + b[:, 2] / 2) / r, 0, w)
        y2 = np.clip((b[:, 1] + b[:, 3] / 2) / r, 0, h)
        boxes = [[float(a), float(c), float(e - a), float(f - c)] for a, c, e, f in zip(x1, y1, x2, y2)]
        idx = cv2.dnn.NMSBoxesBatched(boxes, conf.tolist(), cls.tolist(), self.conf, self.iou)
        res = []
        for i in np.array(idx).flatten():
            box = tuple(float(v) for v in (x1[i] / w, y1[i] / h, x2[i] / w, y2[i] / h))  # JSON-safe
            res.append((box, float(conf[i]), self.names[int(cls[i])]))
        return res

    def __call__(self, img: np.ndarray):
        x, r = self.preprocess(img)
        out = self.sess.run(None, {self.inp: x})[0][0]
        return self.postprocess(out, r, img.shape[1], img.shape[0])
