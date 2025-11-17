# Figure Generation Scripts

## Overview

This directory contains scripts for generating publication-quality figures for Scenario A analysis.

## Main Script

### `generate_all_figures.py` (Recommended)

**Unified script that generates ALL figures for Experiments 2, 3, and 4.**

```bash
# Generate all figures with default settings
python3.12 generate_all_figures.py

# Generate figures to custom directory
python3.12 generate_all_figures.py --output-dir /path/to/output
```

**Generated Figures:**
- **Experiment 2 (Stencil Gadget Catalog)**:
  - `figure_exp2_heatmap.pdf/png` - Gadget type distribution heatmap
  - `figure_exp2_summary_table.pdf/png` - Statistical summary table

- **Experiment 3 (Unaligned Decoding)**:
  - `figure_exp3_offset_comparison.pdf/png` - Offset analysis dual chart

- **Experiment 4 (Patch Function Impact)**:
  - `figure_exp4_patch_impact_scatter.pdf/png` - Pre/post scatter plot
  - `figure_exp4_ranked_impact_table.pdf/png` - Ranked impact table
  - `figure_exp4_patch_function_comparison.pdf/png` - Static vs dynamic distribution
  - `figure_exp4_uop_patch_contribution.pdf/png` - Top uops by patch intensity
  - `figure_exp4_zero_delta_comprehensive.pdf/png` - Multi-panel zero-delta proof
  - `figure_exp4_hypothetical_vs_actual.pdf/png` - Expected vs actual comparison

- **Comprehensive Summary**:
  - `figure_comprehensive_summary.pdf/png` - Multi-panel overview

**Total Output**: 20 files (10 PDF + 10 PNG)

## Features

- **Consistent Styling**: All figures use Times/serif font, 18pt+ text, black colors
- **Publication Quality**: 300 DPI, PDF with embedded TrueType fonts
- **Modular Design**: Easy to add new experiments or modify existing ones
- **Error Handling**: Gracefully handles missing optional data files
- **Progress Feedback**: Clear console output showing generation progress

## Requirements

```bash
pip install matplotlib numpy
```

For extended Experiment 4 analysis, ensure these files exist:
- `scenario_a_patch_analysis.pkl`
- `scenario_a_uop_analysis.pkl`

## Legacy Scripts (Deprecated)

- `generate_publication_figures_old.py` - Original Exp2/3/4 basic figures
- `generate_exp4_figures_old.py` - Original Exp4 extended analysis
- `generate_paper_figures_old.py` - Early version

These are kept for reference but should not be used for new work.

## Architecture

The script is organized into clear sections:

1. **Configuration** - Plot settings, paths, constants
2. **Data Loading** - Load scenario runs and analysis data
3. **Experiment 2** - Stencil catalog visualization
4. **Experiment 3** - Unaligned decoding analysis
5. **Experiment 4 (Basic)** - Patch impact from run data
6. **Experiment 4 (Extended)** - Advanced patch analysis (optional)
7. **Comprehensive Summary** - Multi-panel overview
8. **Utilities** - Helper functions for saving figures

## Customization

To modify plot styles, edit the `PLOT_CONFIG` dictionary at the top of the script:

```python
PLOT_CONFIG = {
    'font.family': 'serif',
    'font.size': 18,
    'axes.labelsize': 20,
    # ... etc
}
```

## Output Location

Default: `gadget_analysis/experiments/20251115_085128_full_scale_6000iters_3xA/results/`

All figures are saved as both PDF (vector) and PNG (raster) for flexibility.
