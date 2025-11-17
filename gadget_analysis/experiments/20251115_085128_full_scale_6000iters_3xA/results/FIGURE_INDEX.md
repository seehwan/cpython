# Figure Index

Quick reference guide for all visualization files in this directory.

---

## 📊 All Figures at a Glance

| Figure | PDF | PNG | Description | Best For |
|--------|-----|-----|-------------|----------|
| **Exp 2: Heat Map** | 32 KB | 145 KB | Gadget type distribution across runs | Paper figures |
| **Exp 2: Summary Table** | 22 KB | 160 KB | Statistical summary table | Paper tables |
| **Exp 3: Offset Comparison** | 22 KB | 212 KB | Unaligned decoding analysis | Research analysis |
| **Exp 4: Scatter Plot** | 21 KB | 285 KB | Pre/post patch comparison | Impact visualization |
| **Exp 4: Ranked Table** | 21 KB | 186 KB | Patch impact ranking | Detailed analysis |
| **Comprehensive Summary** | 40 KB | 527 KB | Multi-panel dashboard | Presentations |

---

## 📁 File Naming Convention

```
figure_[experiment]_[type].[format]

Examples:
  figure_exp2_heatmap.pdf          → Experiment 2, Heat Map, PDF
  figure_exp3_offset_comparison.png → Experiment 3, Offset Charts, PNG
  figure_comprehensive_summary.pdf  → Overall Summary, PDF
```

---

## 🎯 Quick Selection Guide

### For Academic Papers (LaTeX)
**Use PDF files** - vector graphics, scales perfectly, small file size

```latex
% Recommended figures:
\includegraphics{figure_exp2_heatmap.pdf}          % Main results
\includegraphics{figure_exp3_offset_comparison.pdf} % Offset analysis
\includegraphics{figure_exp4_patch_impact_scatter.pdf} % Impact study
```

### For Presentations (PowerPoint/Keynote)
**Use PNG files** - high resolution, better screen rendering

- `figure_comprehensive_summary.png` - Perfect standalone slide
- `figure_exp2_heatmap.png` - Clear type distribution
- `figure_exp3_offset_comparison.png` - Compelling offset data

### For Posters
**Use PDF files** - print quality, any size scaling

Best choices:
- `figure_comprehensive_summary.pdf` - Complete overview
- `figure_exp2_summary_table.pdf` - Detailed statistics

### For Quick Review
**PNG files in image viewer:**
```bash
eog figure_*.png &
```

---

## 🔍 Detailed Figure Descriptions

### `figure_exp2_heatmap` (Experiment 2)
**What it shows:** 7 gadget types × 3 runs heat map  
**Key insight:** pop_rdi dominates with 662-830 instances  
**Use when:** Need to show type distribution visually  
**Paper section:** Results → Gadget Cataloging

### `figure_exp2_summary_table` (Experiment 2)
**What it shows:** Statistical table with mean, std dev, percentages  
**Key insight:** 949.0 ± 147.3 average gadgets  
**Use when:** Need precise numerical data  
**Paper section:** Results → Statistical Analysis

### `figure_exp3_offset_comparison` (Experiment 3)
**What it shows:** Dual bar charts of offset 0-7 analysis  
**Key insight:** Offset 7 yields 16.9% (70% above baseline)  
**Use when:** Demonstrating unaligned decoding advantage  
**Paper section:** Results → Unaligned Instruction Decoding

### `figure_exp4_patch_impact_scatter` (Experiment 4)
**What it shows:** Scatter plot + delta bars  
**Key insight:** All points on diagonal = zero change  
**Use when:** Proving patches don't introduce gadgets  
**Paper section:** Results → Patch Function Impact

### `figure_exp4_ranked_impact_table` (Experiment 4)
**What it shows:** Ranked table of patch impacts  
**Key insight:** All deltas = 0.0 with color coding  
**Use when:** Need detailed impact breakdown  
**Paper section:** Appendix or Supplementary Materials

### `figure_comprehensive_summary`
**What it shows:** 6-panel dashboard with all key metrics  
**Key insight:** Complete overview in one figure  
**Use when:** Presentation slide, poster centerpiece, executive summary  
**Paper section:** Introduction or Discussion summary

---

## 📐 Technical Specifications

### PDF Files
- **Format:** Portable Document Format (vector)
- **Fonts:** Embedded TrueType (Type 42)
- **Colors:** RGB color space
- **Scaling:** Lossless at any size
- **Size:** 21-40 KB per file

### PNG Files
- **Format:** Portable Network Graphics (raster)
- **Resolution:** 300 DPI
- **Color Depth:** 24-bit RGB
- **Compression:** Lossless PNG
- **Size:** 145-527 KB per file

---

## 🚀 Quick Commands

### View All Figures
```bash
# PDFs
evince figure_*.pdf &

# PNGs
eog figure_*.png &

# Or use your preferred viewer
```

### Copy to Paper Directory
```bash
# All PDFs
cp figure_*.pdf /path/to/paper/figures/

# Specific figures
cp figure_exp2_heatmap.pdf figure_exp3_offset_comparison.pdf /path/to/paper/
```

### Check File Sizes
```bash
ls -lh figure_*.pdf figure_*.png
```

### Create Thumbnail Preview
```bash
# Requires ImageMagick
montage figure_*.png -tile 3x2 -geometry 400x300+10+10 preview.png
```

---

## 💡 LaTeX Integration Examples

### Single Figure
```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=0.8\textwidth]{figure_exp2_heatmap.pdf}
  \caption{Gadget type distribution across three runs shows 
           dominant \texttt{pop\_rdi} presence (75.7\%).}
  \label{fig:heatmap}
\end{figure}
```

### Side-by-Side Figures
```latex
\begin{figure}[t]
  \centering
  \begin{subfigure}[b]{0.48\textwidth}
    \includegraphics[width=\textwidth]{figure_exp2_heatmap.pdf}
    \caption{Heat map}
    \label{fig:heat}
  \end{subfigure}
  \hfill
  \begin{subfigure}[b]{0.48\textwidth}
    \includegraphics[width=\textwidth]{figure_exp3_offset_comparison.pdf}
    \caption{Offsets}
    \label{fig:offset}
  \end{subfigure}
  \caption{Gadget analysis results}
  \label{fig:combined}
\end{figure}
```

### Full-Width Figure (Two-Column)
```latex
\begin{figure*}[t]
  \centering
  \includegraphics[width=\textwidth]{figure_comprehensive_summary.pdf}
  \caption{Comprehensive summary dashboard}
  \label{fig:summary}
\end{figure*}
```

---

## 🎨 Color Schemes Used

### Heat Map (Exp 2)
- Colormap: **YlOrRd** (Yellow-Orange-Red)
- Scale: Linear from min to max count
- Annotations: Black (low values) / White (high values)

### Offset Charts (Exp 3)
- Colormap: **Viridis** (0.3-0.9 range)
- Bars: Gradient blue-green-yellow
- Edges: Black outline for clarity

### Scatter Plot (Exp 4)
- Increase: **Green**
- Decrease: **Red**
- No change: **Gray**
- Reference line: Black dashed

### Summary Dashboard
- Run bars: Blue, Orange, Green
- Pie chart: **Set3** colormap
- Mean line: Red dashed
- Confidence band: Gray shaded

---

## 📊 Figure-Specific Recommendations

### For Security Conference Papers (e.g., IEEE S&P, USENIX Security, CCS)
1. `figure_exp2_heatmap.pdf` - Main results
2. `figure_exp3_offset_comparison.pdf` - Attack surface analysis
3. `figure_exp4_patch_impact_scatter.pdf` - Mitigation insights

### For Systems Conference Papers (e.g., SOSP, OSDI, ASPLOS)
1. `figure_comprehensive_summary.pdf` - Performance overview
2. `figure_exp2_summary_table.pdf` - Detailed statistics
3. `figure_exp4_ranked_impact_table.pdf` - Implementation details

### For Thesis/Dissertation
**Use all figures:**
- Chapter 4 (Methodology): Summary table
- Chapter 5 (Results): All experiment-specific figures
- Chapter 6 (Analysis): Comprehensive summary

### For Defense Presentation
**Recommended order:**
1. `figure_comprehensive_summary.png` - Overview (Slide 1)
2. `figure_exp2_heatmap.png` - Main findings (Slide 2)
3. `figure_exp3_offset_comparison.png` - Technical deep dive (Slide 3)
4. `figure_exp4_patch_impact_scatter.png` - Conclusions (Slide 4)

---

## 🔧 Troubleshooting

### LaTeX Won't Compile with PDF
```latex
% Add to preamble:
\usepackage{graphicx}
\usepackage{epstopdf}  % If using older LaTeX
```

### Figures Appear Blurry in Paper
- **Problem:** Using PNG in LaTeX
- **Solution:** Switch to PDF versions (vector graphics)

### Figures Too Large for Slides
- **Problem:** 300 DPI PNGs are high-res
- **Solution:** Scale in PowerPoint or use PDF with appropriate scaling

### Colors Don't Print Well
- **Problem:** RGB colors on CMYK printer
- **Solution:** Convert PDFs to CMYK using Ghostscript:
  ```bash
  gs -dSAFER -dBATCH -dNOPAUSE -dNOCACHE -sDEVICE=pdfwrite \
     -sColorConversionStrategy=CMYK -dProcessColorModel=/DeviceCMYK \
     -sOutputFile=output_cmyk.pdf input.pdf
  ```

---

## 📝 Version History

- **v1.0** (Nov 17, 2025): Initial publication-quality figures generated
- Generated using: `generate_publication_figures.py`
- Python 3.12, matplotlib 3.10, seaborn 0.13

---

**Quick Access:** `cd gadget_analysis/experiments/20251115_085128_full_scale_6000iters_3xA/results/`
