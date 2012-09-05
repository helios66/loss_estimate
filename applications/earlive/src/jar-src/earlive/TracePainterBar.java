package earlive;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Random;

import javax.swing.JFrame;

import info.monitorenter.gui.chart.Chart2D;
import info.monitorenter.gui.chart.ITrace2D;
import info.monitorenter.gui.chart.layout.ChartPanel;
import info.monitorenter.gui.chart.traces.Trace2DSimple;
import info.monitorenter.gui.chart.traces.painters.ATracePainter;


public class TracePainterBar extends ATracePainter {

    private Chart2D m_chart = null;
    private int m_barwidth = 0;
    
    public TracePainterBar(Chart2D chart) {
        this(chart, 10);
    }
    
    public TracePainterBar(Chart2D chart, int width) {
        this.m_barwidth = width;
        this.m_chart = chart;
    }
    
    public void paintPoint(final int absoluteX, final int absoluteY, final int nextX,
            final int nextY, final Graphics2D g) {
        super.paintPoint(absoluteX, absoluteY, nextX, nextY, g);
        g.fillRect(absoluteX-(this.m_barwidth/2), absoluteY, 
                this.m_barwidth, this.m_chart.getYChartStart()-absoluteY);
    }

    /* test case copied from StaticChartFill */
    public static void main(final String[] args) {
        // Create a chart:
        Chart2D chart = new Chart2D();

        // Create an ITrace:
        ITrace2D trace = new Trace2DSimple();
        trace.setTracePainter$30c0137f(new TracePainterBar(chart));
        trace.setColor(Color.DARK_GRAY);
        // Add all points, as it is static:
        double count = 0;
        double value;
        double place = 0;
        Random random = new Random();
        for (int i = 20; i >= 0; i--) {
          count += 1.0;
          place += 1.0;
          value = random.nextDouble() * 10.0 + i;
          trace.addPoint(place, value);
        }
        // Add the trace to the chart:
        chart.addTrace(trace);

        // Make it visible:
        // Create a frame.
        JFrame frame = new JFrame("StaticChartBar");
        // add the chart to the frame:
        frame.getContentPane().add(new ChartPanel(chart));
        frame.setSize(400, 300);
        // Enable the termination button [cross on the upper right edge]:
        frame.addWindowListener(new WindowAdapter() {
          public void windowClosing(final WindowEvent e) {
            System.exit(0);
          }
        });
        frame.setVisible(true);
      }
}
