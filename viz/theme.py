"""차트 공통 테마.

검증된 팔레트를 사용한다 (validate_palette.js 통과).
  categorical: blue #2a78d6 / orange #eb6834 / aqua #1baf7a
  - 인접쌍 CVD ΔE 9.2 (>=8 목표), 정상시야 ΔE 27.6 (>=15 기준) 통과
  - aqua 는 밝은 표면 대비 2.74:1 로 3:1 미만 → **모든 막대에 값 라벨을 직접
    표기**하는 것으로 완화(relief). 색만으로 정보를 전달하지 않는다.

라벨은 영문으로 쓴다. Windows/Linux 어디서 렌더해도 한글 폰트 문제로
글자가 깨지는(tofu) 사고를 원천 차단하기 위함이며, GitHub README 용으로도 적합하다.
"""

from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SURFACE = "#fcfcfb"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID = "#e4e3df"
MUTED = "#9c9b95"          # de-emphasis gray (emphasis 형식용)

SERIES = ["#2a78d6", "#eb6834", "#1baf7a"]  # blue, orange, aqua (고정 순서)

STATUS_CRITICAL = "#d03b3b"
STATUS_GOOD = "#0ca30c"


def apply_base_style() -> None:
    plt.rcParams.update({
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "text.color": TEXT_PRIMARY,
        "axes.labelcolor": TEXT_SECONDARY,
        "xtick.color": TEXT_SECONDARY,
        "ytick.color": TEXT_SECONDARY,
        "axes.edgecolor": GRID,
        "axes.linewidth": 0.8,
        "figure.dpi": 140,
    })


def clean_axes(ax, ygrid: bool = True) -> None:
    """축을 recessive 하게. 위/오른쪽 spine 제거, 그리드는 데이터 뒤로."""
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.spines["left"].set_color(GRID)
    ax.spines["bottom"].set_color(GRID)
    if ygrid:
        ax.yaxis.grid(True, color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
    ax.tick_params(length=0)


def bar_labels(ax, bars, fmt="{:.3f}", dy=0.012, fontsize=8.5) -> None:
    """모든 막대에 값을 직접 표기.

    대비 경고(aqua)에 대한 relief 이자, '색만으로 정보 전달' 금지 원칙의 준수 수단.
    """
    for b in bars:
        h = b.get_height()
        ax.text(b.get_x() + b.get_width() / 2, h + dy, fmt.format(h),
                ha="center", va="bottom", fontsize=fontsize, color=TEXT_SECONDARY)
