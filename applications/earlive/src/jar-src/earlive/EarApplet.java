package earlive;

import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import java.util.Timer;
import java.util.TimerTask;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JApplet;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSlider;
import javax.swing.border.TitledBorder;
import javax.swing.JCheckBox;
import javax.swing.BoxLayout;

import info.monitorenter.gui.chart.Chart2D;
import info.monitorenter.gui.chart.ITrace2D;
import info.monitorenter.gui.chart.TracePoint2D;
import info.monitorenter.gui.chart.rangepolicies.RangePolicyForcedPoint;
import info.monitorenter.gui.chart.traces.Trace2DLtd;


public class EarApplet extends JApplet
{
    private static final long serialVersionUID = 0x3e07e91d1beda083L;
	private final int TRACE_SIZE = 90;// 90 points = 3 minutes
    private final int MINI_TRACE_SIZE = 10;
    
    private long bytes = 0L;
    private int init_time = -TRACE_SIZE;
    private int minute_time = 0;
    private int time = -TRACE_SIZE;
    private int alerts = 0;
    private String url = null;
    private Timer collector = null;
    private DefaultListModel listModel = null;
    
    private Chart2D relChart = null;
    private Chart2D dataChart = null;
    private Chart2D alertChartS = null;  
    private Chart2D alertChart = null;
    private ITrace2D rel_trace = null;
    private ITrace2D data_trace = null;
    private ITrace2D thres_trace = null;
    private ITrace2D alert_trace_s = null;
    private ITrace2D alert_trace = null;
    private TracePoint2D last_point = null;
    
    private JPanel mainPanel = null;
    private JPanel paramPanel = null;
    private JSlider strSlider = null;
    private JSlider destSlider = null;
    private JLabel subsLabel = null;
    private JLabel destLabel = null;
    private JLabel titleLabel = null;
    private JSlider timeSlider = null;
    private JLabel timeLabel = null;
    private JPanel statusPanel = null;
    private JButton updateButton = null;
    private JLabel statusLabel = null;
    private JPanel cardPanel = null;
    private JPanel logPanel = null;
    private JButton logButton = null;
    private JLabel logTitleLabel = null;
    private JList logList = null;
    private JButton backButton = null;
    private JScrollPane logScrollPane = null;
	private JCheckBox jCheckBox = null;
    private JPanel dynChartPanel = null;
	
	
	public EarApplet()
    {
    }
    
    public void destroy()
    {
    }

    public void init()
    {
        boolean online;
        
        url = getCodeBase().toString();
		System.out.println(url);
        createCharts();
        online = isOnline();
        setBounds(new Rectangle(0, 0, 700, 560));
        setContentPane(getCardPanel());

        // set to simple view
        alertChartS.setVisible(false);
        ((CardLayout)dynChartPanel.getLayout()).show(dynChartPanel, "alertChart");
        logButton.setVisible(false);
        
        //all the layout is rendered
        if (online && url != null)
            startCharts();
    }
    
    public static void showError(String title, String msg) {
        JOptionPane.showMessageDialog(null, msg, title,
                JOptionPane.WARNING_MESSAGE);
    }

    private boolean isOnline()
    {
        String response = HttpCom.send(url+"report.php", 
                new String[][]{{"action", "check"}});
        System.out.print(response);
        String resp[] = response.split(":");
        
        if (resp[0].equals("off")) {
            showError("Error in initialization", resp[1]);
            return false;
        }
        else if (resp[0].equals("ok")) {
            return true;
        }
        else {
            showError("Error in 'check' header", "Response : "+resp[0]);
            return false;
        }
    }

    private void createCharts()
    {
        //mini plot (advanced mode)
        alertChartS = new Chart2D();
        alertChartS.setPaintLabels(false);
        alertChartS.setName("alertChartS");
        alertChartS.setBorder(BorderFactory.createTitledBorder(null, "Last ten minutes alerts", TitledBorder.CENTER, TitledBorder.DEFAULT_POSITION, new Font("Dialog", Font.BOLD, 12), new Color(51, 51, 51)));
        alertChartS.getAxisX().setPaintGrid(true);
        alertChartS.getAxisY().setPaintGrid(true);
        alertChartS.getAxisX().setPaintScale(true);
        alertChartS.getAxisY().setPaintScale(true);
        alertChartS.getAxisY().setRangePolicy(new RangePolicyForcedPoint());
        
        alert_trace_s = new Trace2DLtd(MINI_TRACE_SIZE, "Alerts");
        alert_trace_s.setColor(Color.BLUE);
        alert_trace_s.setPhysicalUnits("Alerts", "Minutes");
        alert_trace_s.setTracePainter$30c0137f(new TracePainterBar(alertChartS, 10));
        
        alertChartS.addTrace(alert_trace_s);
        
        //first plot (advanced mode)
        relChart = new Chart2D();
        relChart.setName("relChart");
        relChart.setBorder(BorderFactory.createTitledBorder(null, "Packet similarity value per second", TitledBorder.CENTER, TitledBorder.DEFAULT_POSITION, new Font("Dialog", Font.BOLD, 12), new Color(51, 51, 51)));
        relChart.getAxisX().setPaintGrid(true);
        relChart.getAxisY().setPaintGrid(true);
        relChart.getAxisX().setPaintScale(true);
        relChart.getAxisY().setPaintScale(true);
        
        rel_trace = new Trace2DLtd(TRACE_SIZE, "Similarity");
        rel_trace.setColor(Color.BLUE);
        rel_trace.setPhysicalUnits("Seconds", "Similarity");
        
        thres_trace = new Trace2DLtd(TRACE_SIZE, "Threshold");
        thres_trace.setColor(Color.RED);
        thres_trace.setPhysicalUnits("Seconds", "Similarity");
        
        relChart.addTrace(rel_trace);
        relChart.addTrace(thres_trace);

        //first plot (simple view)
        alertChart = new Chart2D();
        alertChart.setName("alertChart");
        alertChart.setBorder(BorderFactory.createTitledBorder(null, "Alerts per second", TitledBorder.CENTER, TitledBorder.DEFAULT_POSITION, new Font("Dialog", Font.BOLD, 12), new Color(51, 51, 51)));
        alertChart.getAxisX().setPaintGrid(true);
        alertChart.getAxisY().setPaintGrid(true);
        alertChart.getAxisX().setPaintScale(true);
        alertChart.getAxisY().setPaintScale(true);
        alertChart.getAxisY().setRangePolicy(new RangePolicyForcedPoint());
        
        alert_trace = new Trace2DLtd(TRACE_SIZE, "Alerts");
        alert_trace.setColor(Color.BLUE);
        alert_trace.setPhysicalUnits("Seconds", "Alerts");
        alert_trace.setTracePainter$30c0137f(new TracePainterBar(alertChart, 5));
        
        alertChart.addTrace(alert_trace);
        
        // second plot (simple view)
        dataChart = new Chart2D();
        dataChart.setBorder(BorderFactory.createTitledBorder(null, "Bytes processed per second", TitledBorder.CENTER, TitledBorder.DEFAULT_POSITION, new Font("Dialog", Font.BOLD, 12), new Color(51, 51, 51)));
        dataChart.getAxisX().setPaintGrid(true);
        dataChart.getAxisY().setPaintGrid(true);
        dataChart.getAxisX().setPaintScale(true);
        dataChart.getAxisY().setPaintScale(true);
        dataChart.getAxisY().setRangePolicy(new RangePolicyForcedPoint());

        data_trace = new Trace2DLtd(TRACE_SIZE, "Bandwidth");
        data_trace.setColor(Color.GREEN);
        data_trace.setPhysicalUnits("Seconds", "Bytes");
        alertChart.getAxisY().setRangePolicy(new RangePolicyForcedPoint());
        
        dataChart.addTrace(data_trace);

        //charts initialization
        for(int i = -TRACE_SIZE; i < 0; i++) {
            rel_trace.addPoint(new TracePoint2D(i, 0.0D));
            thres_trace.addPoint(new TracePoint2D(i, 0.0D));
            data_trace.addPoint(new TracePoint2D(i, 0.0D));
            alert_trace.addPoint(new TracePoint2D(i, 0.0D));
            if (i >= -MINI_TRACE_SIZE) {
                alert_trace_s.addPoint(new TracePoint2D(i, 0.0D));
            }
        }
        last_point = new TracePoint2D(0, 0);
    }

    private void startCharts()
    {
        TimerTask todo = new TimerTask() {
            public void run() {
                String ans = HttpCom.send(url+"data.php", new String[][] {
                        new String[] {"time", String.valueOf(time)}});
				String lines[] = ans.split("\n");
				for (int i=0; i<lines.length; i++)
                	parseAndSet(lines[i]);
            }
        };
        collector = new Timer("DataCollector");
        collector.schedule(todo, 1000, 2000);
    }
    

    private void parseAndSet(String s)
    {
        boolean goOff=false;
        long new_bytes;
        int new_sim, new_alerts, new_strlen, 
            new_dests, new_timethres;
        
        System.out.println(s);
        String resp[] = s.split(":");
        
        // ear or mapid stopped
        if (resp[0].equals("off")) {
            showError("Error", resp[1]);
            goOff = true;
        }
        //data is not available
        else if (resp[0].equals("na")) {
            ;
        }
        // ok!
        else if (resp[0].equals("ok")) {
            //format : time bytes sim alerts substr dests timethres 
            String data[] = resp[1].split(" |\n");
            try {
                new_bytes = Long.parseLong(data[1]);
                new_sim = Integer.parseInt(data[2]);
                new_alerts = Integer.parseInt(data[3]);
                new_strlen = Integer.parseInt(data[4]);
                new_dests = Integer.parseInt(data[5]);
                new_timethres = Integer.parseInt(data[6]);
                
                if (init_time < 0) {//initialization
                    init_time = time = Integer.parseInt(data[0]); // time
                    strSlider.setValue(new_strlen);
                    destSlider.setValue(new_dests);
                    timeSlider.setValue(new_timethres);
                }
                else {
                    updateCharts(new_bytes, new_sim, new_alerts, new_dests);
                    updateStatusPanel(new_bytes, new_alerts, 
                            new_strlen, new_dests, new_timethres);
                }

                bytes = new_bytes;
                alerts = new_alerts;
                time += 1;
            } catch (NumberFormatException e) {
                showError("Error in data format", e+"\nData :"+resp[1]);
                goOff = true;
            }
        }
        // weird ...
        else {
            showError("Error in data header", "Response: "+resp[0]);
            goOff = true;
        }
        
        if (goOff) //going offline
            collector.cancel();
    }
    
    private void updateCharts(long new_bytes, int new_sim, int new_alerts, int new_dests) {
        int cur_time = 2 * ( time - init_time );
        
        // regular charts
        data_trace.addPoint(new TracePoint2D(cur_time, (new_bytes - bytes) / 2L));
        rel_trace.addPoint(new TracePoint2D(cur_time, new_sim));
        thres_trace.addPoint(new TracePoint2D(cur_time, 1 << new_dests));
        alert_trace.addPoint(new TracePoint2D(cur_time, new_alerts - alerts));

        // mini chart
        if (time - minute_time >= 30) {// 1 time unit = 2 seconds ...
            last_point = new TracePoint2D(last_point.x+1, 0);
            alert_trace_s.addPoint(last_point);
            minute_time = time;
        }
        if (new_alerts - alerts > 0) {
            last_point.y += (new_alerts - alerts);
        }
    }

    private void updateStatusPanel(long new_bytes, int new_alerts, int new_strlen, int new_dests, int new_timethres)
    {
        //uptime 
        int ctime = 2 * time;
        int sec = ctime % 60;
        ctime = (ctime - sec) / 60;
        int min = ctime % 60;
        ctime -= min;
        int hour = ctime / 60;
        
        statusLabel.setText(statusLabel.getText().replaceFirst(
                "[0-9]+:[0-9]+:[0-9]+", hour + ":" + min + ":" + sec));
        
        //bytes processed
        statusLabel.setText(statusLabel.getText().replaceFirst(
                "ssed : [0-9]+", "ssed : " + new_bytes));
        
        //total alerts
        statusLabel.setText(statusLabel.getText().replaceFirst(
                "l Alerts : [0-9]+", "l Alerts : " + (new_alerts)));
        
        //parameters
        statusLabel.setText(statusLabel.getText().replaceFirst(
                "ters : [0-9]+/[0-9]+/[0-9]+", "ters : " + 
                new_strlen + "/" + new_dests + "/" + new_timethres));
    }
    
    private void fillLog() {
        String logs[];
        do {
            logs = HttpCom.send(url+"report.php", new String[][]{
                {"action", "getlog"}, 
                {"line", String.valueOf(listModel.getSize())}}).split("\n");
            for (int i=0; i<logs.length; i++) {
                listModel.addElement(logs[i]);
            }
        } while (logs.length == 0);
    }
    
    /* Visual Editor Code Start */
    private JPanel getMainPanel()
    {
        if(mainPanel == null)
        {
            GridBagConstraints gridBagConstraints16 = new GridBagConstraints();
            gridBagConstraints16.gridx = 0;
            gridBagConstraints16.anchor = GridBagConstraints.CENTER;
            gridBagConstraints16.gridwidth = 2;
            gridBagConstraints16.weighty = 0.4;
            gridBagConstraints16.insets = new Insets(4, 10, 4, 10);
            gridBagConstraints16.fill = GridBagConstraints.BOTH;
            gridBagConstraints16.weightx = 0.0;
            gridBagConstraints16.gridy = 2;
            
            GridBagConstraints gridBagConstraints21 = new GridBagConstraints();
            gridBagConstraints21.gridx = 1;
            gridBagConstraints21.gridy = 0;
            
            GridBagConstraints gridBagConstraints71 = new GridBagConstraints();
            gridBagConstraints71.fill = GridBagConstraints.BOTH;
            gridBagConstraints71.gridy = 3;
            gridBagConstraints71.gridwidth = 2;
            gridBagConstraints71.insets = new Insets(4, 10, 4, 10);
            gridBagConstraints71.anchor = 17;
            gridBagConstraints71.weightx = 0.0;
            gridBagConstraints71.weighty = 0.4;
            gridBagConstraints71.gridx = 0;
            
            GridBagConstraints gridBagConstraints61 = new GridBagConstraints();
            gridBagConstraints61.gridx = 1;
            gridBagConstraints61.fill = GridBagConstraints.BOTH;
            gridBagConstraints61.insets = new Insets(4, 10, 4, 10);
            gridBagConstraints61.gridwidth = 1;
            gridBagConstraints61.anchor = GridBagConstraints.CENTER;
            gridBagConstraints61.weighty = 0.01;
            gridBagConstraints61.weightx = 0.1;
            gridBagConstraints61.gridy = 1;
            
            GridBagConstraints gridBagConstraints31 = new GridBagConstraints();
            gridBagConstraints31.gridx = 0;
            gridBagConstraints31.anchor = GridBagConstraints.CENTER;
            gridBagConstraints31.gridwidth = 0;
            gridBagConstraints31.fill = GridBagConstraints.VERTICAL;
            gridBagConstraints31.weightx = 0.0;
            gridBagConstraints31.weighty = 0.01;
            gridBagConstraints31.insets = new Insets(5, 0, 5, 0);
            gridBagConstraints31.gridy = 0;
            
            titleLabel = new JLabel();
            titleLabel.setText("EAR Online Monitor");
            titleLabel.setFont(new Font("Courier New", Font.BOLD, 20));
            
            GridBagConstraints gridBagConstraints = new GridBagConstraints();
            gridBagConstraints.gridx = 0;
            gridBagConstraints.anchor = 10;
            gridBagConstraints.insets = new Insets(4, 10, 4, 10);
            gridBagConstraints.ipadx = 0;
            gridBagConstraints.fill = GridBagConstraints.BOTH;
            gridBagConstraints.weighty = 0.01;
            gridBagConstraints.weightx = 0.2;
            gridBagConstraints.gridy = 1;
            
            mainPanel = new JPanel();
            mainPanel.setLayout(new GridBagLayout());
            mainPanel.setName("mainPanel");
            mainPanel.add(getDynChartPanel(), gridBagConstraints16);
            mainPanel.add(getParamPanel(), gridBagConstraints);
            mainPanel.add(titleLabel, gridBagConstraints31);
            mainPanel.add(getStatusPanel(), gridBagConstraints61);
            mainPanel.add(dataChart, gridBagConstraints71);
            mainPanel.add(getJCheckBox(), gridBagConstraints21);
        }
        return mainPanel;
    }

    private JPanel getParamPanel()
    {
        if(paramPanel == null)
        {
            GridBagConstraints gridBagConstraints11 = new GridBagConstraints();
            gridBagConstraints11.gridx = 0;
            gridBagConstraints11.gridy = 4;
            
            GridBagConstraints gridBagConstraints13 = new GridBagConstraints();
            gridBagConstraints13.gridx = 1;
            gridBagConstraints13.anchor = GridBagConstraints.CENTER;
            gridBagConstraints13.insets = new Insets(4, 0, 4, 0);
            gridBagConstraints13.gridwidth = 1;
            gridBagConstraints13.gridy = 4;
            
            GridBagConstraints gridBagConstraints7 = new GridBagConstraints();
            gridBagConstraints7.gridx = 0;
            gridBagConstraints7.anchor = 17;
            gridBagConstraints7.insets = new Insets(0, 4, 0, 5);
            gridBagConstraints7.fill = GridBagConstraints.BOTH;
            gridBagConstraints7.weighty = 0.1;
            gridBagConstraints7.gridy = 3;
            timeLabel = new JLabel();
            timeLabel.setText("<html>Time Threshold<br><i>(milli-seconds)</i></html>");
            
            GridBagConstraints gridBagConstraints6 = new GridBagConstraints();
            gridBagConstraints6.fill = GridBagConstraints.BOTH;
            gridBagConstraints6.gridy = 3;
            gridBagConstraints6.weightx = 1.0D;
            gridBagConstraints6.anchor = 13;
            gridBagConstraints6.gridx = 1;
            
            GridBagConstraints gridBagConstraints5 = new GridBagConstraints();
            gridBagConstraints5.gridx = 0;
            gridBagConstraints5.anchor = 17;
            gridBagConstraints5.insets = new Insets(0, 4, 0, 5);
            gridBagConstraints5.fill = GridBagConstraints.BOTH;
            gridBagConstraints5.weighty = 0.1;
            gridBagConstraints5.gridy = 2;
            destLabel = new JLabel();
            destLabel.setText("Destinations Threshold");
            
            GridBagConstraints gridBagConstraints4 = new GridBagConstraints();
            gridBagConstraints4.gridx = 0;
            gridBagConstraints4.anchor = 17;
            gridBagConstraints4.insets = new Insets(0, 4, 0, 5);
            gridBagConstraints4.fill = GridBagConstraints.BOTH;
            gridBagConstraints4.weighty = 0.1;
            gridBagConstraints4.gridy = 1;
            subsLabel = new JLabel();
            subsLabel.setText("<html>Sub-String Length<br><i>(bytes)</i></html>");
            
            GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
            gridBagConstraints2.fill = GridBagConstraints.BOTH;
            gridBagConstraints2.gridy = 2;
            gridBagConstraints2.weightx = 1.0D;
            gridBagConstraints2.anchor = 13;
            gridBagConstraints2.gridx = 1;
            
            GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
            gridBagConstraints1.fill = GridBagConstraints.BOTH;
            gridBagConstraints1.gridy = 1;
            gridBagConstraints1.weightx = 1.0D;
            gridBagConstraints1.anchor = 13;
            gridBagConstraints1.gridx = 1;
            
            paramPanel = new JPanel();
            paramPanel.setLayout(new GridBagLayout());
            paramPanel.setBorder(BorderFactory.createTitledBorder(null, "Parameters", 0, 0, null, null));
            paramPanel.add(getStrSlider(), gridBagConstraints1);
            paramPanel.add(getDestSlider(), gridBagConstraints2);
            paramPanel.add(subsLabel, gridBagConstraints4);
            paramPanel.add(destLabel, gridBagConstraints5);
            paramPanel.add(getTimeSlider(), gridBagConstraints6);
            paramPanel.add(timeLabel, gridBagConstraints7);
            paramPanel.add(getUpdateButton(), gridBagConstraints13);
            paramPanel.add(getLogButton(), gridBagConstraints11);
        }
        return paramPanel;
    }

    private JSlider getStrSlider()
    {
        if(strSlider == null)
        {
            strSlider = new JSlider();
            strSlider.setName("str_len");
            strSlider.setPaintTicks(true);
            strSlider.setSnapToTicks(true);
            strSlider.setMajorTickSpacing(200);
            strSlider.setMinimum(200);
            strSlider.setMaximum(1000);
            strSlider.setMinorTickSpacing(50);
            strSlider.setExtent(0);
            strSlider.setPaintLabels(true);
        }
        return strSlider;
    }

    private JSlider getDestSlider()
    {
        if(destSlider == null)
        {
            destSlider = new JSlider();
            destSlider.setMaximum(20);
            destSlider.setMinorTickSpacing(1);
            destSlider.setName("dest_thres");
            destSlider.setPaintLabels(true);
            destSlider.setPaintTicks(true);
            destSlider.setValue(0);
            destSlider.setMajorTickSpacing(2);
            destSlider.setSnapToTicks(true);
            destSlider.setMinimum(2);
        }
        return destSlider;
    }

    private JSlider getTimeSlider()
    {
        if(timeSlider == null)
        {
            timeSlider = new JSlider();
            timeSlider.setMajorTickSpacing(500);
            timeSlider.setMinimum(500);
            timeSlider.setMinorTickSpacing(100);
            timeSlider.setPaintLabels(true);
            timeSlider.setPaintTicks(true);
            timeSlider.setName("time_thres");
            timeSlider.setSnapToTicks(true);
            timeSlider.setMaximum(3000);
        }
        return timeSlider;
    }

    private JPanel getStatusPanel()
    {
        if(statusPanel == null)
        {
            statusLabel = new JLabel();
            statusLabel.setText("<html>Uptime : 00:00:00<br>Bytes Processed : 0<br>Total Alerts : 0<br>Current Parameters : 0/0/0</html>");
            statusLabel.setAlignmentX(RIGHT_ALIGNMENT);
            statusPanel = new JPanel();
            statusPanel.setLayout(new BoxLayout(getStatusPanel(), BoxLayout.Y_AXIS));
            statusPanel.setBorder(BorderFactory.createTitledBorder(null, "Status", 0, 0, null, null));
            statusPanel.add(statusLabel, null);
            statusPanel.add(alertChartS, null);
        }
        return statusPanel;
    }

    private JButton getUpdateButton()
    {
        if(updateButton == null)
        {
            updateButton = new JButton();
            updateButton.setText("Update Values");
            updateButton.addMouseListener(new MouseListener() {

                public void mouseClicked(MouseEvent e)
                {
                    HttpCom.send(url+"report.php", new String[][] {
                        new String[] {
                            "action", "cparams"
                        }, new String[] {
                            "str_len", String.valueOf(strSlider.getValue())
                        }, new String[] {
                            "dest_thres", String.valueOf(destSlider.getValue())
                        }, new String[] {
                            "time_thres", String.valueOf(timeSlider.getValue())
                        }
                    });
                }

                public void mousePressed(MouseEvent mouseevent)
                {
                }

                public void mouseReleased(MouseEvent mouseevent)
                {
                }

                public void mouseEntered(MouseEvent mouseevent)
                {
                }

                public void mouseExited(MouseEvent mouseevent)
                {
                }
            });
        }
        return updateButton;
    }

    /**
     * This method initializes cardPanel	
     * 	
     * @return javax.swing.JPanel	
     */
    private JPanel getCardPanel() {
        if (cardPanel == null) {
            cardPanel = new JPanel();
            cardPanel.setLayout(new CardLayout());
            cardPanel.add(getMainPanel(), getMainPanel().getName());
            cardPanel.add(getLogPanel(), getLogPanel().getName());
        }
        return cardPanel;
    }

    /**
     * This method initializes logPanel	
     * 	
     * @return javax.swing.JPanel	
     */
    private JPanel getLogPanel() {
        if (logPanel == null) {
            GridBagConstraints gridBagConstraints15 = new GridBagConstraints();
            gridBagConstraints15.fill = GridBagConstraints.BOTH;
            gridBagConstraints15.weighty = 1.0;
            gridBagConstraints15.gridx = 0;
            gridBagConstraints15.gridy = 1;
            gridBagConstraints15.insets = new Insets(10, 10, 10, 10);
            gridBagConstraints15.weightx = 1.0;
            
            GridBagConstraints gridBagConstraints12 = new GridBagConstraints();
            gridBagConstraints12.gridx = 0;
            gridBagConstraints12.insets = new Insets(5, 5, 5, 0);
            gridBagConstraints12.gridy = 2;
            
            GridBagConstraints gridBagConstraints9 = new GridBagConstraints();
            gridBagConstraints9.gridx = 0;
            gridBagConstraints9.insets = new Insets(5, 0, 5, 0);
            gridBagConstraints9.ipadx = 0;
            gridBagConstraints9.gridy = 0;
            
            logTitleLabel = new JLabel();
            logTitleLabel.setText("EAR Log View");
            logTitleLabel.setFont(new Font("Courier New", Font.BOLD, 20));
            logPanel = new JPanel();
            logPanel.setLayout(new GridBagLayout());
            logPanel.setName("logPanel");
            logPanel.add(logTitleLabel, gridBagConstraints9);
            logPanel.add(getLogScrollPane(), gridBagConstraints15);
            logPanel.add(getBackButton(), gridBagConstraints12);
        }
        return logPanel;
    }

    /**
     * This method initializes logButton	
     * 	
     * @return javax.swing.JButton	
     */
    private JButton getLogButton() {
        if (logButton == null) {
            logButton = new JButton();
            logButton.setText("View Log");
            logButton.addMouseListener(new java.awt.event.MouseListener() {
                public void mouseClicked(java.awt.event.MouseEvent e) {
                    ((CardLayout)cardPanel.getLayout()).show(cardPanel, "logPanel");
                    fillLog();
                }
                public void mousePressed(java.awt.event.MouseEvent e) {
                }
                public void mouseReleased(java.awt.event.MouseEvent e) {
                }
                public void mouseEntered(java.awt.event.MouseEvent e) {
                }
                public void mouseExited(java.awt.event.MouseEvent e) {
                }
            });
        }
        return logButton;
    }

    /**
     * This method initializes logList	
     * 	
     * @return javax.swing.JList	
     */
    private JList getLogList() {
        if (logList == null) {
            listModel = new DefaultListModel();
            logList = new JList(listModel);
        }
        return logList;
    }

    /**
     * This method initializes backButton	
     * 	
     * @return javax.swing.JButton	
     */
    private JButton getBackButton() {
        if (backButton == null) {
            backButton = new JButton();
            backButton.setText("<< Back");
            backButton.addMouseListener(new java.awt.event.MouseListener() {
                public void mouseClicked(java.awt.event.MouseEvent e) {
                    ((CardLayout)cardPanel.getLayout()).show(cardPanel, "mainPanel");
                }
                public void mousePressed(java.awt.event.MouseEvent e) {
                }
                public void mouseReleased(java.awt.event.MouseEvent e) {
                }
                public void mouseEntered(java.awt.event.MouseEvent e) {
                }
                public void mouseExited(java.awt.event.MouseEvent e) {
                }
            });
        }
        return backButton;
    }

    /**
     * This method initializes logScrollPane	
     * 	
     * @return javax.swing.JScrollPane	
     */
    private JScrollPane getLogScrollPane() {
        if (logScrollPane == null) {
            logScrollPane = new JScrollPane();
            logScrollPane.setViewportView(getLogList());
        }
        return logScrollPane;
    }

	/**
	 * This method initializes jCheckBox	
	 * 	
	 * @return javax.swing.JCheckBox	
	 */
	private JCheckBox getJCheckBox() {
		if (jCheckBox == null) {
			jCheckBox = new JCheckBox();
			jCheckBox.setText("Advanced View");
			jCheckBox.addItemListener(new ItemListener() {
				public void itemStateChanged(ItemEvent e) {
					if (e.getStateChange() == ItemEvent.SELECTED) {
					    //Advanced view
                        ((CardLayout)dynChartPanel.getLayout()).show(dynChartPanel, "relChart");
                        alertChartS.setVisible(true);
                        logButton.setVisible(true);
					}
					else if (e.getStateChange() == ItemEvent.DESELECTED) {
					    //Simple view
                        ((CardLayout)dynChartPanel.getLayout()).show(dynChartPanel, "alertChart");
                        alertChartS.setVisible(false);
                        logButton.setVisible(false);
					}
				}
			});
		}
		return jCheckBox;
	}

    /**
     * This method initializes dynChartPanel	
     * 	
     * @return javax.swing.JPanel	
     */
    private JPanel getDynChartPanel() {
        if (dynChartPanel == null) {
            CardLayout cardLayout = new CardLayout();
            dynChartPanel = new JPanel();
            dynChartPanel.setLayout(cardLayout);
            dynChartPanel.add(relChart, relChart.getName());
            dynChartPanel.add(alertChart, alertChart.getName());
        }
        return dynChartPanel;
    }
    
    /*Visual Editor Code End*/
}
