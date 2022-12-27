use plotters::style::colors;

use clap::Parser;
use plotters::drawing::IntoDrawingArea;
use plotters::style::Color;
use plotters::style::IntoFont;

fn main() {
    let args = Args::parse();

    let measurements = (0..args.points).map(|point| {
        let num_signers = args.num_signers * 2usize.pow(point);
        let num_signatures = args.num_signers * 2usize.pow(point);

        (
            num_signers,
            frost::simulation::simulate(num_signatures, num_signatures),
        )
    });

    logplot(measurements).unwrap();
}

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(short, long, default_value_t = 10)]
    num_signers: usize,

    #[arg(short = 't', long, default_value_t = 6)]
    num_signatures: usize,

    #[arg(short, long, default_value_t = 10)]
    points: u32,
}

fn logplot(
    measurements: impl IntoIterator<Item = (usize, frost::simulation::Stats)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let series_to_plot = loglog_series(measurements);

    let (x_range, y_range) = series_to_plot
        .iter()
        .map(|series| (series.x_range, series.y_range))
        .reduce(|left, right| (left.0.combine(&right.0), left.1.combine(&right.1)))
        .expect("No data to plot");

    let root =
        plotters::backend::BitMapBackend::new("plots/result.png", (640, 480)).into_drawing_area();
    root.fill(&colors::WHITE)?;

    let mut chart = plotters::chart::ChartBuilder::on(&root)
        .caption(
            format!("Frost bandwidth utilization"),
            ("sans-serif", 30).into_font(),
        )
        .margin(5)
        .x_label_area_size(30)
        .y_label_area_size(30)
        .build_cartesian_2d(x_range.0..x_range.1, y_range.0..y_range.1)?;

    chart.configure_mesh().draw()?;

    for (series, color) in series_to_plot
        .into_iter()
        .zip([colors::CYAN, colors::GREEN, colors::MAGENTA].into_iter())
    {
        chart
            .draw_series(plotters::series::LineSeries::new(series.values, color))?
            .label(series.label)
            .legend(move |(x, y)| {
                plotters::element::PathElement::new(vec![(x, y), (x + 20, y)], color)
            });
    }

    chart
        .configure_series_labels()
        .background_style(&colors::WHITE.mix(0.8))
        .border_style(&colors::BLACK)
        .draw()?;

    chart
        .configure_mesh()
        .y_desc("Transmitted bytes (log 10)")
        .x_desc("Number of signers (log 10)")
        .draw()?;

    root.present()?;

    Ok(())
}

fn loglog_series(
    series: impl IntoIterator<Item = (usize, frost::simulation::Stats)>,
) -> [Series; 3] {
    let mut nonce_distribution_series = Series::new("Nonce distribution".into());
    let mut secret_distribution_series = Series::new("Secret distribution".into());
    let mut sig_aggregation_series = Series::new("Signature aggregation".into());

    for (num_signers, stats) in series {
        let log_num_signers = (num_signers as f64).log10() as f32;
        let log_nonce_distribution =
            (stats.total_nonce_distribution_bandwidth as f64).log10() as f32;
        let log_secret_distribution =
            (stats.total_secret_distribution_bandwidth as f64).log10() as f32;
        let log_sig_aggregation = (stats.total_sig_bandwidth as f64).log10() as f32;

        nonce_distribution_series.add_point(log_num_signers, log_nonce_distribution);
        secret_distribution_series.add_point(log_num_signers, log_secret_distribution);
        sig_aggregation_series.add_point(log_num_signers, log_sig_aggregation);
    }

    [
        nonce_distribution_series,
        secret_distribution_series,
        sig_aggregation_series,
    ]
}

struct Series {
    label: String,
    values: Vec<(f32, f32)>,
    x_range: Range,
    y_range: Range,
}

impl Series {
    fn new(label: String) -> Self {
        Self {
            label,
            values: Vec::new(),
            x_range: Range(f32::MAX, f32::MIN),
            y_range: Range(f32::MAX, f32::MIN),
        }
    }

    fn add_point(&mut self, x: f32, y: f32) {
        self.values.push((x, y));
        self.x_range.0 = self.x_range.0.min(x);
        self.x_range.1 = self.x_range.1.max(x);

        self.y_range.0 = self.y_range.0.min(y);
        self.y_range.1 = self.y_range.1.max(y);
    }
}

#[derive(Clone, Copy)]
struct Range(f32, f32);

impl Range {
    fn combine(&self, other: &Self) -> Range {
        Self(self.0.min(other.0), self.1.max(other.1))
    }
}
