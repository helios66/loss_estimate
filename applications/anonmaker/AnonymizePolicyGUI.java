import java.awt.*;
import javax.swing.*;
import java.awt.event.*;
import java.util.*;
import java.io.*;

class AnonymizeFunction {
	String function_name;
	String friendly_name;
	boolean takesNoArguments;
	
	public AnonymizeFunction(String line) throws Exception {
		takesNoArguments=true;
		StringTokenizer tokenizer=new StringTokenizer(line,",");
		
		if(tokenizer.countTokens()<2) {
			System.out.print("Invalid function specification");
			throw new Exception("Invalid Function Specification");
		}
		
		function_name=new String(tokenizer.nextToken());
		String f=tokenizer.nextToken();
		friendly_name=new String(f.substring(1,f.length()-1));

		if(tokenizer.countTokens()>0) {
			takesNoArguments=false;
		}
	}
	public boolean takesNoArguments() {
		return(this.takesNoArguments);
	}

	public String getName() {
		return this.function_name;
	}

	public String getFriendlyName() {
		return friendly_name;
	}
}

class FunctionMenuItem extends JMenuItem {
	AnonymizeFunction function;	

	public FunctionMenuItem(AnonymizeFunction f) {
		super(f.getFriendlyName());
		this.function=f;
	}

	public AnonymizeFunction getFunction() {
		return function;
	}
	
}

class HeaderField extends JPanel implements MouseListener,ActionListener{
	JLabel label;
	Vector functions; //which functions are available
	String[] exclusionList=null; //which we should exclude
	String functionApplied; //what function was applied
	Vector functionParameters; //paramaters of the function applied
	String name;  //its name in the anonymization header file
	JFrame parent=null;
	String protocol=null; //the protocol it belongs
	String checksumBehavior;

	public HeaderField(String name,String title,int width,Vector f) {
		this(name,title,width,f,null);
	}
	
	public HeaderField(String name,String title,int width,Vector f,String[] exclusionList) {
		this.functions=f;
		this.exclusionList=exclusionList;
		this.name=name;
		
		functionApplied=new String("UNCHANGED");
		checksumBehavior=new String("UNCHANGED");
		functionParameters=new Vector();

		setBorder(BorderFactory.createCompoundBorder(BorderFactory.createTitledBorder(title),
                        BorderFactory.createEmptyBorder(1,1,1,1)));
		setPreferredSize(new Dimension(width,45));
		label=new JLabel("UNCHANGED");
		add(label);
		addMouseListener(this);
	}

	public String getFunctionApplied() {
		return functionApplied;
	}

	public String getName() {
		return name;
	}

	public String getProtocol() {
		return protocol;
	}

	public String getChecksumBehavior() {
		return checksumBehavior;
	}
	
	public Vector getFunctionParameters() {
		return functionParameters;
	}

	public void setProtocol(String proto) {
		this.protocol=new String(proto);
	}

	public void setExclusionList(String[] list) {
		this.exclusionList=list;
	}
	
	public boolean insideExclusionList(String name) {
		if(exclusionList==null) 
			return false;
			
		for(int k=0;k<exclusionList.length;k++) {
			if(exclusionList[k].compareTo(name)==0)
				return true;
		}
		return false;
	}

	public void setParent(JFrame fr) {
		this.parent=fr;
	}

	JFrame stripFrame;
	JTextField stripBytesField;
	
	public void showStripInput() {
		stripFrame=new JFrame("Replace Function Parameters");
		
		stripFrame.addWindowListener(new WindowAdapter() {
          public void windowClosing(WindowEvent e) {
             parent.setEnabled(true);
          }
        });

		JPanel inputpanel=new JPanel(new GridLayout(3,1));
		inputpanel.add(new JLabel("Type the number of fields"));
		inputpanel.add(new JLabel("to keep from the field"));
		stripBytesField=new JTextField("0");
		inputpanel.add(stripBytesField);

		JPanel okcancelPanel=new JPanel(new GridLayout(1,3));
		okcancelPanel.add(new JLabel(""));
		
		JButton stripok=new JButton("OK");
		stripok.addActionListener(this);
		stripok.setActionCommand("strip_ok");
		okcancelPanel.add(stripok);
		
		JButton stripcancel=new JButton("Cancel");
		stripcancel.addActionListener(this);
		stripcancel.setActionCommand("strip_cancel");
		okcancelPanel.add(stripcancel);
		
		JPanel total=new JPanel(new BorderLayout());
		total.add(inputpanel,BorderLayout.CENTER);
		total.add(okcancelPanel,BorderLayout.SOUTH);

		parent.setEnabled(false);
		
		stripFrame.getContentPane().add(total);
		stripFrame.pack();
		stripFrame.setResizable(false);
        stripFrame.setVisible(true);

	}


	JFrame replaceFrame;
	JTextField replacePatternField;
	
	public void showReplaceInput() {
		System.out.println("I am showReplaceInput");
		replaceFrame=new JFrame("Replace Function Parameters");
		
		replaceFrame.addWindowListener(new WindowAdapter() {
          public void windowClosing(WindowEvent e) {
             parent.setEnabled(true);
          }
        });

		JPanel inputpanel=new JPanel(new GridLayout(3,1));

		inputpanel.add(new JLabel("Provide a pattern or"));
		inputpanel.add(new JLabel("leave blank to let user specify it"));
		replacePatternField=new JTextField("test");
		inputpanel.add(replacePatternField);

		JPanel okcancelPanel=new JPanel(new GridLayout(1,3));
		okcancelPanel.add(new JLabel(""));
		
		JButton replaceok=new JButton("OK");
		replaceok.addActionListener(this);
		replaceok.setActionCommand("replace_ok");
		okcancelPanel.add(replaceok);
		
		JButton replacecancel=new JButton("Cancel");
		replacecancel.addActionListener(this);
		replacecancel.setActionCommand("replace_cancel");
		okcancelPanel.add(replacecancel);
		
		JPanel total=new JPanel(new BorderLayout());
		total.add(inputpanel,BorderLayout.CENTER);
		total.add(okcancelPanel,BorderLayout.SOUTH);

		parent.setEnabled(false);
		
		replaceFrame.getContentPane().add(total);
		replaceFrame.pack();
		replaceFrame.setResizable(false);
        replaceFrame.setVisible(true);
		//inputPanel
	}

	JCheckBox[] hashAlgorithms;
	String[] hashAlgorithmsNames;
	JFrame hashFrame;

	public void showHashInput() {
		hashFrame=new JFrame("Hash Function Parameters");
		//hashFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		hashAlgorithms=new JCheckBox[]{new JCheckBox("MD5"),new JCheckBox("SHA"),new JCheckBox("SHA-256"),new JCheckBox("CRC32"),new JCheckBox("AES"),new JCheckBox("DES"),new JCheckBox("Triple DES",true)};
		hashAlgorithmsNames=new String[]{"MD5","SHA","SHA_2","CRC32","AES","DES","TRIPLE_DES"};
		
		JPanel hashPanel=new JPanel(new GridLayout(3,3));
		hashPanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createTitledBorder("Allowed Hash Functions"),BorderFactory.createEmptyBorder(1,1,1,1)));
		
		hashFrame.addWindowListener(new WindowAdapter() {
          public void windowClosing(WindowEvent e) {
             parent.setEnabled(true);
          }
        });
		
		for(int g=0;g<hashAlgorithms.length;g++) {
			hashPanel.add(hashAlgorithms[g]);
		}
			
		JPanel okcancelPanel=new JPanel(new GridLayout(1,3));
		okcancelPanel.add(new JLabel(""));
		
		JButton hashok=new JButton("OK");
		hashok.addActionListener(this);
		hashok.setActionCommand("hash_ok");
		okcancelPanel.add(hashok);
		
		JButton hashcancel=new JButton("Cancel");
		hashcancel.addActionListener(this);
		hashcancel.setActionCommand("hash_cancel");
		okcancelPanel.add(hashcancel);

		JPanel total=new JPanel(new BorderLayout());
		total.add(hashPanel,BorderLayout.CENTER);
		total.add(okcancelPanel,BorderLayout.SOUTH);

		parent.setEnabled(false);

		hashFrame.getContentPane().add(total);
		hashFrame.pack();
		hashFrame.setResizable(false);
        hashFrame.setVisible(true);

		
	}

	JFrame distributionFrame;
	JTextField median,deviation;
	JTextField lowerlimit,upperlimit;
	JCheckBox gaussian,uniform;

	public void showDistributionInput() {
		distributionFrame=new JFrame("Distribution Function Parameters");
		
		distributionFrame.addWindowListener(new WindowAdapter() {
          public void windowClosing(WindowEvent e) {
             parent.setEnabled(true);
          }
        });

		JPanel distrPanel=new JPanel(new GridLayout(1,2));
		
		gaussian=new JCheckBox("Allow Gaussian");
		median=new JTextField("40");
		deviation=new JTextField("5");
		uniform=new JCheckBox("Allow Uniform");
		lowerlimit=new JTextField("0");
		upperlimit=new JTextField("256");
		
		JPanel gaussianpanel=new JPanel(new BorderLayout());
		gaussianpanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createTitledBorder(""),BorderFactory.createEmptyBorder(1,1,1,1)));
		gaussianpanel.add(gaussian,BorderLayout.NORTH);
		JPanel middlegaussian=new JPanel(new GridLayout(2,2));
		middlegaussian.add(new JLabel("Median"));
		middlegaussian.add(median);
		middlegaussian.add(new JLabel("Standard Deviation"));
		middlegaussian.add(deviation);
		gaussianpanel.add(middlegaussian,BorderLayout.CENTER);
	
		JPanel uniformpanel=new JPanel(new BorderLayout());
		uniformpanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createTitledBorder(""),BorderFactory.createEmptyBorder(1,1,1,1)));
		uniformpanel.add(uniform,BorderLayout.NORTH);
		JPanel middleuniform=new JPanel(new GridLayout(2,2));
		middleuniform.add(new JLabel("Lower limit"));
		middleuniform.add(lowerlimit);
		middleuniform.add(new JLabel("Upper limit"));
		middleuniform.add(upperlimit);
		uniformpanel.add(middleuniform,BorderLayout.CENTER);

		distrPanel.add(gaussianpanel);
		distrPanel.add(uniformpanel);
		
		JPanel okcancelPanel=new JPanel(new GridLayout(1,3));
		okcancelPanel.add(new JLabel(""));

		JButton distrok=new JButton("OK");
		distrok.addActionListener(this);
		distrok.setActionCommand("distr_ok");
		okcancelPanel.add(distrok);
		
		JButton distrcancel=new JButton("Cancel");
		distrcancel.addActionListener(this);
		distrcancel.setActionCommand("distr_cancel");
		okcancelPanel.add(distrcancel);

		JPanel total=new JPanel(new BorderLayout());
		total.add(distrPanel,BorderLayout.CENTER);
		total.add(okcancelPanel,BorderLayout.SOUTH);

		parent.setEnabled(false);

		distributionFrame.getContentPane().add(total);
		distributionFrame.pack();
		distributionFrame.setResizable(false);
        distributionFrame.setVisible(true);

	}
	
	JFrame regexFrame;
	JTextField regexstring, regexreplace;

	public void showRegexInput() {
		regexFrame=new JFrame("Regular Expression Function Parameters");
		regexFrame.addWindowListener(new WindowAdapter() {
          public void windowClosing(WindowEvent e) {
             parent.setEnabled(true);
          }
        });

		JPanel mainpanel=new JPanel(new GridLayout(3,1));
		JPanel uppanel=new JPanel(new BorderLayout());
		uppanel.add(new JLabel("Regular Expression"),BorderLayout.WEST);
		regexstring=new JTextField("a*http*b",16);
		uppanel.add(regexstring,BorderLayout.CENTER);

		JPanel middlepanel=new JPanel(new BorderLayout());
		middlepanel.add(new JLabel("Substitution String"),BorderLayout.WEST);
		regexreplace=new JTextField("NULL,NULL",16);
		middlepanel.add(regexreplace,BorderLayout.CENTER);
	
		mainpanel.add(uppanel);
		mainpanel.add(middlepanel);
		
		JButton regexok=new JButton("OK");
		regexok.addActionListener(this);
		regexok.setActionCommand("regex_ok");

		JButton regexcancel=new JButton("Cancel");
		regexcancel.addActionListener(this);
		regexcancel.setActionCommand("regex_cancel");
		
		JPanel okcancelPanel=new JPanel(new GridLayout(1,3));
		okcancelPanel.add(new JLabel(""));
		okcancelPanel.add(regexok);
		okcancelPanel.add(regexcancel);
		mainpanel.add(okcancelPanel);
		
		parent.setEnabled(false);
		regexFrame.getContentPane().add(mainpanel);
		regexFrame.pack();
		regexFrame.setResizable(false);
        regexFrame.setVisible(true);
		
	}

	JFrame fillFrame;
	JTextField patternString;
	JCheckBox fillString,fillInt;
	JTextField fillMinInt,fillMaxInt;

	public void showFillInput() {
		fillFrame=new JFrame("Pattern Fill Function Parameters");
		
		fillFrame.addWindowListener(new WindowAdapter() {
          public void windowClosing(WindowEvent e) {
             parent.setEnabled(true);
          }
        });

		JPanel fillpanel=new JPanel(new BorderLayout());
		
		JPanel stringpanel=new JPanel(new BorderLayout());
		stringpanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createTitledBorder(""),BorderFactory.createEmptyBorder(1,1,1,1)));

		fillString=new JCheckBox("Allow Fill with string");
		JPanel minipanel=new JPanel(new BorderLayout());
		minipanel.add(new JLabel("String: "),BorderLayout.WEST);
		patternString=new JTextField("abcdef...",16);
		minipanel.add(patternString,BorderLayout.CENTER);
		stringpanel.add(fillString,BorderLayout.NORTH);
		stringpanel.add(minipanel,BorderLayout.SOUTH);

		JPanel intpanel=new JPanel(new BorderLayout());
		intpanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createTitledBorder(""),BorderFactory.createEmptyBorder(1,1,1,1)));
		fillInt=new JCheckBox("Allow Fill with integer");
		intpanel.add(fillInt,BorderLayout.NORTH);
		JPanel minipanel2=new JPanel(new BorderLayout());
		minipanel2.add(new JLabel("Integer: "),BorderLayout.WEST);
		fillMinInt=new JTextField("0",10);
		minipanel2.add(fillMinInt,BorderLayout.CENTER);
		//minipanel2.add(new JLabel("Maximum allowable integer: "));
		//fillMaxInt=new JTextField("256",10);
		//minipanel2.add(fillMaxInt);
		intpanel.add(minipanel2,BorderLayout.CENTER);

		fillpanel.add(stringpanel,BorderLayout.WEST);
		fillpanel.add(intpanel,BorderLayout.CENTER);
		
	
		JPanel okcancelPanel=new JPanel(new GridLayout(1,3));
		okcancelPanel.add(new JLabel(""));

		JButton fillok=new JButton("OK");
		fillok.addActionListener(this);
		fillok.setActionCommand("fill_ok");
		okcancelPanel.add(fillok);
		
		JButton fillcancel=new JButton("Cancel");
		fillcancel.addActionListener(this);
		fillcancel.setActionCommand("fill_cancel");
		okcancelPanel.add(fillcancel);

		JPanel total=new JPanel(new BorderLayout());
		total.add(fillpanel,BorderLayout.CENTER);
		total.add(okcancelPanel,BorderLayout.SOUTH);

		parent.setEnabled(false);

		fillFrame.getContentPane().add(total);
		fillFrame.pack();
		fillFrame.setResizable(false);
        fillFrame.setVisible(true);

	}

	
	/*public void askForChecksum() {
		int csum=JOptionPane.showConfirmDialog(parent,"Do you want checksum adjustment?","Checksum Adjustment", 
				JOptionPane.YES_NO_OPTION,JOptionPane.QUESTION_MESSAGE);
				if(csum==JOptionPane.YES_OPTION) {
					checksumBehavior="CHECKSUM_ADJUSTMENT";
				}
				else {
					checksumBehavior="UNCHANGED";
				}
	}*/
	
	public void actionPerformed(ActionEvent e) {
		AnonymizeFunction f=null;
		String command;
		
		if(e.getSource() instanceof FunctionMenuItem) {
			f=((FunctionMenuItem)(e.getSource())).getFunction();
			command=f.getName();
		}
		else 
			command=e.getActionCommand();
		
	
		if(f!=null && f.takesNoArguments()) {
				functionApplied=f.getName();
				label.setText(f.getName());
		}
		else if(command.equals("REPLACE")) {
			showReplaceInput();
		}
		else if(command.equals("MAP_DISTRIBUTION")) {
			showDistributionInput();
		}
		else if(command.equals("STRIP")) {
			showStripInput();
		}
		else if(command.equals("HASHED")) {
			showHashInput();
		}
		else if(command.equals("PATTERN_FILL")) {
			showFillInput();
		}
		else if(command.equals("REGEXP")) {
			showRegexInput();
		}
		else if(command.equals("hash_ok")) {
			boolean selected=false;
			for(int k=0;k<hashAlgorithms.length;k++) {
				if(hashAlgorithms[k].isSelected()) {
					selected=true;
					break;
				}
			}

			if(selected==false) {
				JOptionPane.showMessageDialog(hashFrame,"No algorithms were selected. At least one must be selected.",
				"Hash algorithm selection error",JOptionPane.ERROR_MESSAGE);
			}
			else {
				functionApplied="HASHED";
				parent.setEnabled(true);
				// save parameters
				functionParameters.clear();
				for(int k=0;k<hashAlgorithms.length;k++) {
					if(hashAlgorithms[k].isSelected()) {
						functionParameters.add(new String(hashAlgorithmsNames[k]));
					}
				}
				hashFrame.dispose();
				label.setText("HASHED");
			}
		}
		else if(command.equals("hash_cancel")) {
			parent.setEnabled(true);
			hashFrame.dispose();
		}
		else if(command.equals("replace_ok")) {
			if(replacePatternField.getText().equals("")) {
				JOptionPane.showMessageDialog(hashFrame,"No pattern was typed.",
				"Pattern selection error",JOptionPane.ERROR_MESSAGE);
			}
			else {
				functionApplied="REPLACE";
				//save parameters
				functionParameters.clear();
				functionParameters.add(new String(replacePatternField.getText()));	
				parent.setEnabled(true);
				replaceFrame.dispose();
				label.setText("REPLACE with \""+replacePatternField.getText()+"\"");
			}
		}
		else if(command.equals("replace_cancel")) {
			parent.setEnabled(true);
			replaceFrame.dispose();
		}
		else if(command.equals("strip_ok")) {
			if(stripBytesField.getText().equals("")) {
				JOptionPane.showMessageDialog(stripFrame,"The number of bytes to be kept is undeclared",
				"Strip input error",JOptionPane.ERROR_MESSAGE);
			}
			else {
				boolean isInteger=false;
				int k=0;
				try {
					k=(new Integer(0)).parseInt(stripBytesField.getText());
					isInteger=true;
				}
				catch(Exception w) {
				}

				if(!isInteger) {
					JOptionPane.showMessageDialog(stripFrame,"The number of bytes is not an integer",
					"Strip input error",JOptionPane.ERROR_MESSAGE);
				}
				else {
					parent.setEnabled(true);
					functionApplied="STRIP";
					//save parameters
					functionParameters.clear();
					functionParameters.add(new String(stripBytesField.getText()));	
					stripFrame.dispose();
					label.setText("STRIP and keep "+k+" bytes");
				}
			}
		}
		else if(command.equals("strip_cancel")) {
			parent.setEnabled(true);
			stripFrame.dispose();
		}
		else if(command.equals("distr_ok")) {
			if(!gaussian.isSelected() && !uniform.isSelected()) {
				JOptionPane.showMessageDialog(stripFrame,"At least one type must be selected",
					"Distribution input error",JOptionPane.ERROR_MESSAGE);
			}
			else {
				boolean all_filled=true;
				
				if(gaussian.isSelected() && (median.getText().equals("") || deviation.getText().equals(""))) {
					JOptionPane.showMessageDialog(stripFrame,"Median and deviation must be both specified when Gaussian distribution is allowed","Distribution input error",JOptionPane.ERROR_MESSAGE);
					all_filled=false;
				}
				
				if(uniform.isSelected() && (lowerlimit.getText().equals("") || upperlimit.getText().equals(""))) {
					JOptionPane.showMessageDialog(distributionFrame,"Lower and upper limit must be both specified when Uniform distribution is allowed","Distribution input error",JOptionPane.ERROR_MESSAGE);
					all_filled=false;
				}
				
				if(all_filled) {
					boolean all_types_ok=true;
					
					if(gaussian.isSelected()) {
						try {
							(new Integer(0)).parseInt(median.getText());
						}
						catch(Exception e1) {
							all_types_ok=false;
							JOptionPane.showMessageDialog(distributionFrame,"Median value is not an integer","Distribution input error",JOptionPane.ERROR_MESSAGE);
							
						}
						
						try {
							(new Integer(0)).parseInt(deviation.getText());
						}
						catch(Exception e2) {
							all_types_ok=false;
							JOptionPane.showMessageDialog(distributionFrame,"Deviation value is not an integer","Distribution input error",JOptionPane.ERROR_MESSAGE);
						
						}
					}

					if(uniform.isSelected()) {

						try {
							(new Integer(0)).parseInt(lowerlimit.getText());
						}
						catch(Exception e3) {
							all_types_ok=false;
							JOptionPane.showMessageDialog(distributionFrame,"Lower limit is not an integer","Distribution input error",JOptionPane.ERROR_MESSAGE);
						}
						
						try {
							(new Integer(0)).parseInt(upperlimit.getText());
						}
						catch(Exception e4) {
							all_types_ok=false;
							JOptionPane.showMessageDialog(distributionFrame,"Upper limit is not an integer","Distribution input error",JOptionPane.ERROR_MESSAGE);
						}

					}

					if(all_types_ok) {
						parent.setEnabled(true);
						functionApplied="MAP_DISTRIBUTION";
						functionParameters.clear();
						if(gaussian.isSelected()) {
							functionParameters.add(new String("GAUSSIAN"));	
							functionParameters.add(new String(median.getText()));	
							functionParameters.add(new String(deviation.getText()));	
						}
						if(uniform.isSelected()) {
							functionParameters.add(new String("UNIFORM"));	
							functionParameters.add(new String(lowerlimit.getText()));	
							functionParameters.add(new String(upperlimit.getText()));	
						}
						distributionFrame.dispose();
						label.setText("MAP_DISTRIBUTION");
					}

				}
				
			}
		}
		else if(command.equals("distr_cancel")) {
			parent.setEnabled(true);
			distributionFrame.dispose();
		}
		else if(command.equals("regex_ok")) {
			boolean allok=true;
			if(regexstring.getText().equals("")) {
				allok=false;
				JOptionPane.showMessageDialog(regexFrame,"Regular Expression is not defined","Regular Expression input error",JOptionPane.ERROR_MESSAGE);
			}
			
			if(regexreplace.getText().equals("")) {
				allok=false;
				JOptionPane.showMessageDialog(regexFrame,"Substitution string is not defined","Regular Expression input error",JOptionPane.ERROR_MESSAGE);
			}

			if(allok) {
				functionApplied="REGEX";
				functionParameters.clear();
				
				functionParameters.add(new String(regexstring.getText()));
				functionParameters.add(new String(regexreplace.getText()));
				
				parent.setEnabled(true);
				regexFrame.dispose();
				label.setText("REGEX");
			}
			
		}
		else if(command.equals("regex_cancel")) {
			System.out.print("hiiii\n");
			parent.setEnabled(true);
			regexFrame.dispose();
		}
		else if(command.equals("fill_ok")) {
			if(!fillString.isSelected() && !fillInt.isSelected()) {
				JOptionPane.showMessageDialog(fillFrame,"At least one type of pattern fill must be selected","Fill Pattern input error",JOptionPane.ERROR_MESSAGE);
			}
			else {
				boolean all_filled=true;
				
				if(fillString.isSelected() && patternString.getText().equals("")) {
					all_filled=false;
					JOptionPane.showMessageDialog(fillFrame,"String was not defined","Fill Pattern input error",JOptionPane.ERROR_MESSAGE);
					
				}

				if(fillInt.isSelected() && fillMinInt.getText().equals("")) {
					all_filled=false;
					JOptionPane.showMessageDialog(fillFrame,"Integer was not defined","Fill Pattern input error",JOptionPane.ERROR_MESSAGE);
				}

				if(all_filled) {
					boolean types_ok=true;

					if(fillInt.isSelected()) {
						try {
							(new Integer(0)).parseInt(fillMinInt.getText());
						}
						catch(Exception e5) {
							types_ok=false;
							JOptionPane.showMessageDialog(fillFrame,"The integer you types is not an integer :)","Fill Pattern input error",JOptionPane.ERROR_MESSAGE);
						}
					}

					if(types_ok) {
						parent.setEnabled(true);
						functionApplied="PATTERN_FILL";
						
						functionParameters.clear();
						
						if(fillString.isSelected()) {
							functionParameters.add(new String("STR"));
							functionParameters.add(new String(patternString.getText()));
						}
						
						if(fillInt.isSelected()) {
							functionParameters.add(new String("INTEGER"));
							functionParameters.add(new String(fillMinInt.getText()));
						}
						
						fillFrame.dispose();
						label.setText("PATTERN_FILL");

					}
				}
			}
		}
		else if(command.equals("fill_cancel")) {
			parent.setEnabled(true);
			fillFrame.dispose();
		}


	}
	
	public void mouseClicked(MouseEvent e) {
		
		int mask = InputEvent.BUTTON1_MASK - 1;
        int mods = e.getModifiers() & mask;
        if (mods == 0) {
            // Left button clicked
			System.out.println("left");
        }
        else { //right click
			JPopupMenu popup = new JPopupMenu();
			
			for(int i=0;i<functions.size();i++) {
				AnonymizeFunction f=(AnonymizeFunction)functions.elementAt(i);
				if(!insideExclusionList(f.getName())) {
					FunctionMenuItem item=new FunctionMenuItem(f);
					item.addActionListener(this);
					popup.add(item);
				}
			}
			popup.show( e.getComponent(),e.getX(),e.getY() );
			
        }
	}

 	public void mouseEntered(MouseEvent e) {}
 	public void mouseExited(MouseEvent e) {}
 	public void mousePressed(MouseEvent e) {}
 	public void mouseReleased(MouseEvent e) {}
}

interface HeaderPanelInterface {
	abstract String createKeynoteCode();
	abstract String createMapiCode();
}

class FTPHeaderPanel extends JPanel {
	Vector functionsVector;
	Vector fields;
	int WIDTH=770;
	int HEIGHT=450;

	public FTPHeaderPanel(Vector v,JFrame frame) {
		this.functionsVector=v;
		
		setLayout(new GridBagLayout());
		setPreferredSize(new Dimension(WIDTH,HEIGHT));
		GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
		HeaderField field;
		JLabel empty;
		
		for(int i=0;i<4;i++) {
			empty=new JLabel("  ");
			empty.setPreferredSize(new Dimension(WIDTH/4,10));
        	c.weightx = 0.5;
			c.gridx = i;
        	c.gridy = 0;
			c.gridwidth=1;
        	add(empty, c);
		}
		
		fields=new Vector();
		
		addField("FTP_RESPONSE_CODE","Response Code",WIDTH/4,0,1,2,c,new String[]{"PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("FTP_RESPONSE_ARG","Response Argument",WIDTH/4,2,1,2,c,new String[]{"PREFIX_PRESERVING","CHECKSUM_ADJUST"});

		
		addField("USER","Username",WIDTH/4,0,2,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("PASS","Password",WIDTH/4,1,2,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("ACCT","ACCT",WIDTH/4,2,2,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("FTP_TYPE","Type",WIDTH/4,3,2,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});

		addField("STRU","STRU",WIDTH/4,0,3,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("MODE","MODE",WIDTH/4,1,3,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("CWD","CWD",WIDTH/4,2,3,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("PWD","PWD",WIDTH/4,3,3,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		
		addField("CDUP","CDUP",WIDTH/4,0,4,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("PASV","PASV",WIDTH/4,1,4,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("RETR","RETR",WIDTH/4,2,4,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("REST","REST",WIDTH/4,3,4,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		
		addField("PORT","PORT",WIDTH/4,0,5,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("LIST","LIST",WIDTH/4,1,5,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("NLST","NLST",WIDTH/4,2,5,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("QUIT","QUIT",WIDTH/4,3,5,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});

		addField("SYST","SYST",WIDTH/4,0,6,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("STAT","STAT",WIDTH/4,1,6,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("HELP","HELP",WIDTH/4,2,6,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("NOOP","NOOP",WIDTH/4,3,6,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		
		addField("STOR","STOR",WIDTH/4,0,7,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("APPE","APPE",WIDTH/4,1,7,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("STOU","STOU",WIDTH/4,2,7,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("ALLO","ALLO",WIDTH/4,3,7,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		
		addField("MKD","Make Dir",WIDTH/4,0,8,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("RMD","Remove Dir",WIDTH/4,1,8,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("DELE","Delete File",WIDTH/4,2,8,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("RNFR","RNFR",WIDTH/4,3,8,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		
		addField("RNTO","RNTO",WIDTH/4,0,9,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("SITE","SITE",WIDTH/4,1,9,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		
		
		for(int g=0;g<fields.size();g++) {
			((HeaderField)fields.elementAt(g)).setParent(frame);
			((HeaderField)fields.elementAt(g)).setProtocol("FTP");
		}

	}
	
	public void addField(String define,String descr,int width,int gridx,int gridy,int gridwidth,GridBagConstraints c,String[] exclList) {
		HeaderField  h= new HeaderField(define,descr,width,functionsVector);
		h.setExclusionList(exclList);
		fields.add(h);
        c.gridx = gridx;
        c.gridy = gridy;
		c.gridwidth=gridwidth;
        add(h, c);
	}

	public Dimension getPanelSize() {
		return new Dimension(WIDTH,HEIGHT);
	}

	public Vector getFields() {
		return this.fields;
	}

}

class HTTPHeaderPanel extends JPanel {
	Vector functionsVector;
	Vector fields;
	int WIDTH=770;
	int HEIGHT=730;

	public HTTPHeaderPanel(Vector v,JFrame frame) {
		this.functionsVector=v;
		
		setLayout(new GridBagLayout());
		setPreferredSize(new Dimension(WIDTH,HEIGHT));
		GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
		HeaderField field;
		JLabel empty;
		
		for(int i=0;i<4;i++) {
			empty=new JLabel("  ");
			empty.setPreferredSize(new Dimension(WIDTH/4,10));
        	c.weightx = 0.5;
			c.gridx = i;
        	c.gridy = 0;
			c.gridwidth=1;
        	add(empty, c);
		}

		fields=new Vector();
		
		addField("METHOD","Method (GET/POST/..)",WIDTH/4,0,1,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("URI","URI",WIDTH/2,1,1,2,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("HTTP_VERSION","HTTP Version",WIDTH/4,3,1,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});

		addField("HTTP_VERSION","HTTP Version",WIDTH/4,0,2,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("RESPONSE_CODE","Response Code (200/403/..)",WIDTH/4,1,2,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("RESP_CODE_DESCR","Response Code Description",WIDTH/2,2,2,2,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});	
		
		addField("USER_AGENT","User Agent",WIDTH/4,0,3,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});	
		addField("ACCEPT","Accept",WIDTH/4,1,3,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});		
		addField("ACCEPT_CHARSET","Accept Charset",WIDTH/4,2,3,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("ACCEPT_ENCODING","Accept Encoding",WIDTH/4,3,3,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});		

		addField("ACCEPT_LANGUAGE","Accept Language",WIDTH/4,0,4,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("ACCEPT_RANGES","Accept Ranges",WIDTH/4,1,4,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("AGE","Age",WIDTH/4,2,4,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});		
		addField("ALLOW","Allow",WIDTH/4,3,4,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		
		addField("AUTHORIZATION","Authorization",WIDTH/4,0,5,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("CACHE_CONTROL","Cache control",WIDTH/4,1,5,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("CONNECTION_TYPE","Connection Type",WIDTH/4,2,5,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("CONTENT_TYPE","Content Type",WIDTH/4,3,5,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});

		
		addField("CONTENT_LENGTH","Content Length",WIDTH/4,0,6,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});		
		addField("CONTENT_LOCATION","Content Location",WIDTH/4,1,6,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("CONTENT_MD5","Content MD5",WIDTH/4,2,6,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("CONTENT_RANGE","Content Range",WIDTH/4,3,6,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		
		addField("CONTENT_ENCODING","Content Encoding",WIDTH/4,0,7,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("ETAG","Etag",WIDTH/4,1,7,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("EXPECT","Expect",WIDTH/4,2,7,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("EXPIRES","Expires",WIDTH/4,3,7,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		
		addField("FROM","From",WIDTH/4,0,8,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("HOST","Host",WIDTH/4,1,8,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});		
		addField("IF_MATCH","If Match",WIDTH/4,2,8,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("IF_MODIFIED_SINCE","If Modified Since",WIDTH/4,3,8,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		
		addField("IF_NONE_MATCH","If None Match",WIDTH/4,0,9,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("IF_RANGE","If Range",WIDTH/4,1,9,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("IF_UNMODIFIED_SINCE","If Unmodified Since",WIDTH/4,2,9,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("LAST_MODIFIED","Last Modified",WIDTH/4,3,9,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});

		addField("MAX_FORWRDS","Max Forwards",WIDTH/4,0,10,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("PRAGMA","Pragma",WIDTH/4,1,10,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("PROXY_AUTHENTICATE","Proxy Authenticate",WIDTH/4,2,10,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("PROXY_AUTHORIZATION","Proxy Authorization",WIDTH/4,3,10,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING"});
	
		addField("RANGE","Range",WIDTH/4,0,11,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("REFERRER","Referrer",WIDTH/4,1,11,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});		
		addField("RETRY_AFTER","Retry After",WIDTH/4,2,11,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("SET_COOKIE","Set Cookie",WIDTH/4,3,11,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});

		addField("SERVER","Server",WIDTH/4,0,12,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("TE","TE",WIDTH/4,1,12,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("TRAILER","Trailer",WIDTH/4,2,12,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("TRANSFER_ENCODING","Transfer Encoding",WIDTH/4,3,12,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
	
		addField("UPGRADE","Upgrade",WIDTH/4,0,13,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("VIA","Via",WIDTH/4,1,13,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("WARNING","Warning",WIDTH/4,2,13,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("WWW_AUTHENTICATE","WWW Authenticate",WIDTH/4,3,13,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		
		addField("X_POWERED_BY","X Powered By",WIDTH/4,0,14,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("VARY","Vary",WIDTH/4,1,14,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("DATE","Date",WIDTH/4,2,14,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("KEEP_ALIVE","Keep Alive",WIDTH/4,3,14,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
	
		addField("LOCATION","Location",WIDTH/4,0,15,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		addField("COOKIE","Cookie",WIDTH/4,1,15,1,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
	
		addField("HTTP_PAYLOAD","HTTP Payload",WIDTH,0,16,4,c,new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
	
		for(int g=0;g<fields.size();g++) {
			((HeaderField)fields.elementAt(g)).setParent(frame);
			((HeaderField)fields.elementAt(g)).setProtocol("HTTP");
		}

	}

	public void addField(String define,String descr,int width,int gridx,int gridy,int gridwidth,GridBagConstraints c,String[] exclList) {
		HeaderField  h= new HeaderField(define,descr,width,functionsVector);
		h.setExclusionList(exclList);
		fields.add(h);
        c.gridx = gridx;
        c.gridy = gridy;
		c.gridwidth=gridwidth;
        add(h, c);
	}
	
	public Dimension getPanelSize() {
		return new Dimension(WIDTH,HEIGHT);
	}

	public Vector getFields() {
		return this.fields;
	}

	
}

class ICMPHeaderPanel extends JPanel {
	Vector functionsVector;
	Vector fields;
	int WIDTH=750;
	int HEIGHT=120;
	
	public ICMPHeaderPanel(Vector v,JFrame frame) {
		this.functionsVector=v;
		
		setLayout(new GridBagLayout());
		setPreferredSize(new Dimension(WIDTH,HEIGHT));
		GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
		HeaderField field;
		JLabel empty;
		
		for(int i=0;i<4;i++) {
			empty=new JLabel("  "+i*8);
			empty.setPreferredSize(new Dimension(WIDTH/4,10));
        	c.weightx = 0.5;
			c.gridx = i;
        	c.gridy = 0;
			c.gridwidth=1;
        	add(empty, c);
		}

		fields=new Vector();
		
		HeaderField type = new HeaderField("TYPE","Type",WIDTH/4,functionsVector);
		type.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(type);
        c.gridx = 0;
        c.gridy = 1;
		c.gridwidth=1;
        add(type, c);
		
		HeaderField code = new HeaderField("CODE","Code",WIDTH/4,functionsVector);
		code.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(code);
        c.gridx = 1;
        c.gridy = 1;
		c.gridwidth=1;
        add(code, c);

		HeaderField csum = new HeaderField("CHECKSUM","Checksum",WIDTH/2,functionsVector);
		csum.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","REPLACE"});
		fields.add(csum);
        c.gridx = 2;
        c.gridy = 1;
		c.gridwidth=2;
        add(csum, c);
		
		HeaderField payload = new HeaderField("PAYLOAD","ICMP Payload",WIDTH,functionsVector);
		payload.setExclusionList(new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		fields.add(payload);
        c.gridx = 0;
        c.gridy = 2;
		c.gridwidth=4;
        add(payload, c);

		for(int g=0;g<fields.size();g++) {
			((HeaderField)fields.elementAt(g)).setParent(frame);
			((HeaderField)fields.elementAt(g)).setProtocol("ICMP");
		}

	}

	public Dimension getPanelSize() {
		return new Dimension(WIDTH,HEIGHT);
	}

	public Vector getFields() {
		return this.fields;
	}

}

class UDPHeaderPanel extends JPanel {
	Vector functionsVector;
	Vector fields;
	int WIDTH=750;
	int HEIGHT=170;
	
	public UDPHeaderPanel(Vector v,JFrame frame) {
		this.functionsVector=v;

        setLayout(new GridBagLayout());
		setPreferredSize(new Dimension(WIDTH,HEIGHT));
		GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
		HeaderField field;
		JLabel empty;
		
		for(int i=0;i<2;i++) {
			empty=new JLabel("  "+i*16);
			empty.setPreferredSize(new Dimension(WIDTH/2,10));
        	c.weightx = 0.5;
			c.gridx = i;
        	c.gridy = 0;
			c.gridwidth=1;
        	add(empty, c);
		}
		
		fields=new Vector();
		
		HeaderField src_port = new HeaderField("SRC_PORT","Source Port",WIDTH/2,functionsVector);
		src_port.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(src_port);
        c.gridx = 0;
        c.gridy = 1;
		c.gridwidth=1;
        add(src_port, c);
		
		HeaderField dst_port = new HeaderField("DST_PORT","Destination Port",WIDTH/2,functionsVector);
		dst_port.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(dst_port);
        c.gridx = 1;
        c.gridy = 1;
		c.gridwidth=1;
        add(dst_port, c);

		HeaderField udp_length = new HeaderField("UDP_DATAGRAM_LENGTH","Datagram Length",WIDTH/2,functionsVector);
		udp_length.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(udp_length);
        c.gridx = 0;
        c.gridy = 2;
		c.gridwidth=1;
        add(udp_length, c);
		
		HeaderField udp_csum = new HeaderField("CHECKSUM","Checksum",WIDTH/2,functionsVector);
		udp_length.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","REPLACE"});
		fields.add(udp_csum);
        c.gridx = 1;
        c.gridy = 2;
		c.gridwidth=1;
        add(udp_csum, c);
		
		HeaderField udp_payload = new HeaderField("PAYLOAD","UDP payload",WIDTH,functionsVector);
		udp_payload.setExclusionList(new String[]{"MAP","MAP_DISTRIBUTION","STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		fields.add(udp_payload);
        c.gridx = 0;
        c.gridy = 3;
		c.gridwidth=2;
        add(udp_payload, c);

		for(int g=0;g<fields.size();g++) {
			((HeaderField)fields.elementAt(g)).setParent(frame);
			((HeaderField)fields.elementAt(g)).setProtocol("UDP");
		}

	}
	
	public Dimension getPanelSize() {
		return new Dimension(WIDTH,HEIGHT);
	}

	public Vector getFields() {
		return this.fields;
	}

}

class TCPHeaderPanel extends JPanel {
	Vector functionsVector;
	Vector fields;
	int WIDTH=750;
	int HEIGHT=350;

	public TCPHeaderPanel(Vector v,JFrame frame) {
		this.functionsVector=v;

        setLayout(new GridBagLayout());
		setPreferredSize(new Dimension(WIDTH,HEIGHT));
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
		JLabel empty;
		
		for(int i=0;i<4;i++) {
			empty=new JLabel("  "+i*8);
			empty.setPreferredSize(new Dimension(WIDTH/4,10));
        	c.weightx = 0.5;
			c.gridx = i;
        	c.gridy = 0;
			c.gridwidth=1;
        	add(empty, c);
		}

		fields=new Vector();
		
		HeaderField src_port = new HeaderField("SRC_PORT","Source Port",WIDTH/2,functionsVector);
		src_port.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(src_port);
        c.gridx = 0;
        c.gridy = 1;
		c.gridwidth=2;
        add(src_port, c);
		
		HeaderField dst_port = new HeaderField("DST_PORT","Destination Port",WIDTH/2,functionsVector);
		dst_port.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(dst_port);
        c.gridx = 2;
        c.gridy = 1;
		c.gridwidth=2;
        add(dst_port, c);
		
		HeaderField sequence = new HeaderField("SEQUENCE_NUMBER","Sequence Number",WIDTH,functionsVector);
		sequence.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(sequence);
        c.gridx = 0;
        c.gridy = 2;
		c.gridwidth=4;
        add(sequence, c);

		HeaderField ackn = new HeaderField("ACK_NUMBER","Acknowledgement Number",WIDTH,functionsVector);
		ackn.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(ackn);
        c.gridx = 0;
        c.gridy = 3;
		c.gridwidth=4;
        add(ackn, c);
			
		HeaderField offset = new HeaderField("OFFSET_AND_RESERVED","Offset and Reserved",WIDTH/4,functionsVector);
		offset.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(offset);
        c.gridx = 0;
        c.gridy = 4;
		c.gridwidth=1;
        add(offset, c);

		HeaderField flags = new HeaderField("FLAGS","Flags",WIDTH/4,functionsVector);
		flags.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(flags);
        c.gridx = 1;
        c.gridy = 4;
		c.gridwidth=1;
        add(flags, c);
		
		HeaderField window = new HeaderField("WINDOW","Window",WIDTH/2,functionsVector);
		window.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(window);
        c.gridx = 2;
        c.gridy = 4;
		c.gridwidth=2;
        add(window, c);
		
		HeaderField csum = new HeaderField("CHECKSUM","Checksum",WIDTH/2,functionsVector);
		csum.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(csum);
        c.gridx = 0;
        c.gridy = 5;
		c.gridwidth=2;
        add(csum, c);
		
		HeaderField urgent = new HeaderField("URGENT_POINTER","Urgent pointer",WIDTH/2,functionsVector);
		urgent.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(urgent);
        c.gridx = 2;
        c.gridy = 5;
		c.gridwidth=2;
        add(urgent, c);
	
		HeaderField options = new HeaderField("TCP_OPTIONS","Options",WIDTH,functionsVector);
		options.setExclusionList(new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		fields.add(options);
        c.gridx = 0;
        c.gridy = 6;
		c.gridwidth=4;
        add(options, c);
		
		HeaderField payload = new HeaderField("PAYLOAD","TCP Payload",WIDTH,functionsVector);
		payload.setExclusionList(new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","CHECKSUM_ADJUST"});
		fields.add(payload);
        c.gridx = 0;
        c.gridy = 7;
		c.gridwidth=4;
        add(payload, c);
		
		for(int g=0;g<fields.size();g++) {
			((HeaderField)fields.elementAt(g)).setParent(frame);
			((HeaderField)fields.elementAt(g)).setProtocol("TCP");
		}
		
	}
	
	public Dimension getPanelSize() {
		return new Dimension(WIDTH,HEIGHT);
	}

	public Vector getFields() {
		return this.fields;
	}
}

class IPHeaderPanel extends JPanel {
	Vector functionsVector;
	Vector fields;
	int WIDTH=750;
	int HEIGHT=350;

	public IPHeaderPanel(Vector v,JFrame frame) {

		this.functionsVector=v;

        setLayout(new GridBagLayout());
		setPreferredSize(new Dimension(WIDTH,HEIGHT));
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
		HeaderField field;
		JLabel empty;
		
		for(int i=0;i<4;i++) {
			empty=new JLabel("  "+i*8);
			empty.setPreferredSize(new Dimension(WIDTH/4,10));
        	c.weightx = 0.5;
			c.gridx = i;
        	c.gridy = 0;
			c.gridwidth=1;
        	add(empty, c);
		}

		fields=new Vector();
		
		JPanel vihl=new JPanel(new GridLayout(1,2));
		HeaderField version=new HeaderField("VERSION","Version",WIDTH/8,functionsVector);
		version.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","HASHED","CHECKSUM_ADJUST","REPLACE"});
		HeaderField ihl=new HeaderField("IHL","IHL",WIDTH/8,functionsVector);
		ihl.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(version);
		fields.add(ihl);
		vihl.add(version);
		vihl.add(ihl);
		vihl.setPreferredSize(new Dimension(WIDTH/4,45));
	
        c.gridx = 0;
        c.gridy = 1;
		c.gridwidth=1;
        add(vihl, c);

        HeaderField tos = new HeaderField("TOS","ToS",WIDTH/4,functionsVector);
		tos.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(tos);
        c.gridx = 1;
        c.gridy = 1;
		c.gridwidth=1;
        add(tos, c);
		
		HeaderField tlength = new HeaderField("PACKET_LENGTH","Total Length",WIDTH/2,functionsVector);
		tlength.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(tlength);
        c.gridx = 2;
        c.gridy = 1;
		c.gridwidth=2;
        add(tlength, c);

       	HeaderField ipid = new HeaderField("ID","Identification",WIDTH/2,functionsVector);
		ipid.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(ipid);
        c.gridx = 0;
        c.gridy = 2;
		c.gridwidth=2;
        add(ipid, c);

	    HeaderField offset = new HeaderField("FRAGMENT_OFFSET","Fragment offset",WIDTH/2,functionsVector);
		offset.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(offset);
        c.gridx = 2;
        c.gridy = 2;
		c.gridwidth=2;
        add(offset, c);

		HeaderField ttl = new HeaderField("TTL","Time-To-Live",WIDTH/4,functionsVector);
		ttl.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(ttl);
        c.gridx = 0;
        c.gridy = 3;
		c.gridwidth=1;
        add(ttl, c);

		HeaderField protocol = new HeaderField("IP_PROTO","Protocol",WIDTH/4,functionsVector);
		protocol.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","CHECKSUM_ADJUST","REPLACE"});
		fields.add(protocol);
        c.gridx = 1;
        c.gridy = 3;
		c.gridwidth=1;
        add(protocol, c);

		HeaderField checksum = new HeaderField("CHECKSUM","Checksum",WIDTH/2,functionsVector);
		checksum.setExclusionList(new String[]{"STRIP","PREFIX_PRESERVING","REPLACE"});
		fields.add(checksum);
        c.gridx = 2;
        c.gridy = 3;
		c.gridwidth=2;
        add(checksum, c);
		
		HeaderField srcip = new HeaderField("SRC_IP","Source IP address",WIDTH,functionsVector);
		srcip.setExclusionList(new String[]{"STRIP","CHECKSUM_ADJUST","REPLACE"});
		fields.add(srcip);
        c.gridx = 0;
        c.gridy = 4;
		c.gridwidth=4;
        add(srcip, c);

		HeaderField dstip = new HeaderField("DST_IP","Destination IP address",WIDTH,functionsVector);
		dstip.setExclusionList(new String[]{"STRIP","CHECKSUM_ADJUST","REPLACE"});
		fields.add(dstip);
        c.gridx = 0;
        c.gridy = 5;
		c.gridwidth=4;
        add(dstip, c);

	   	HeaderField ipopts = new HeaderField("OPTIONS","Options",WIDTH,functionsVector);
		ipopts.setExclusionList(new String[]{"MAP","MAP_DISTRIBUTION","PREFIX_PRESERVING","HASHED","CHECKSUM_ADJUST"});
		fields.add(ipopts);
        c.gridx = 0;
        c.gridy = 6;
		c.gridwidth=4;
        add(ipopts, c);

		HeaderField ippayload = new HeaderField("PAYLOAD","IP Payload",WIDTH,functionsVector);
		ippayload.setExclusionList(new String[]{"MAP","MAP_DISTRIBUTION","CHECKSUM_ADJUST"});
		fields.add(ippayload);
        c.gridx = 0;
        c.gridy = 7;
		c.gridwidth=4;
        add(ippayload, c);

		for(int g=0;g<fields.size();g++) {
			((HeaderField)fields.elementAt(g)).setParent(frame);
			((HeaderField)fields.elementAt(g)).setProtocol("IP");
		}

	}
	
	public Dimension getPanelSize() {
		return new Dimension(WIDTH,HEIGHT);
	}

	public Vector getFields() {
		return this.fields;
	}

}

class ProtocolGroup {
	String name;
	IPHeaderPanel ipHeaderPanel;
	UDPHeaderPanel udpHeaderPanel;
	ICMPHeaderPanel icmpHeaderPanel;
	TCPHeaderPanel tcpHeaderPanel;
	HTTPHeaderPanel httpHeaderPanel;
	FTPHeaderPanel ftpHeaderPanel;

	boolean cookingApplied=false,uncookApplied=false;
	Vector allowedFuncsBeforeAnon;
	Vector enforcedFunctions=null;
	Vector deletedFuncs=null;

	public ProtocolGroup(String n,Vector functionsVector,JFrame frame) {
		this.name=n;
		allowedFuncsBeforeAnon=new Vector();
		ipHeaderPanel=new IPHeaderPanel(functionsVector,frame);	
		udpHeaderPanel=new UDPHeaderPanel(functionsVector,frame);
		icmpHeaderPanel=new ICMPHeaderPanel(functionsVector,frame);
		tcpHeaderPanel=new TCPHeaderPanel(functionsVector,frame);
		httpHeaderPanel=new HTTPHeaderPanel(functionsVector,frame);
		ftpHeaderPanel=new FTPHeaderPanel(functionsVector,frame);
	}

	public String getName() {
		return this.name;
	}

	public IPHeaderPanel getIPHeader() {
		return ipHeaderPanel;
	}

	public UDPHeaderPanel getUDPHeader() {
		return udpHeaderPanel;
	}

	public ICMPHeaderPanel getICMPHeader() {
		return icmpHeaderPanel;
	}
	
	public TCPHeaderPanel getTCPHeader() {
		return tcpHeaderPanel;
	}
	
	public HTTPHeaderPanel getHTTPHeader() {
		return httpHeaderPanel;
	}

	public FTPHeaderPanel getFTPHeader() {
		return ftpHeaderPanel;
	}

	public String createMapiCodeFromField(HeaderField h,boolean colorize) {
		String mapiline="";

		if(colorize) {
			mapiline="<strong>mapi_apply_function</strong>(<em>fd</em>,<strong><font color=red>\"ANONYMIZE\"</font>,";
			mapiline+="<font color=blue>"+h.getProtocol()+"</font>,<font color=green>"+h.getName()+"</font>,<font color=purple>"+h.getFunctionApplied()+"</font></strong>";
			//mapiline+="</font></strong>,<em>"+h.getChecksumBehavior()+"</em>";
		}
		else {
			mapiline="mapi_apply_function(fd,\"ANONYMIZE\",";
			mapiline+=h.getProtocol()+","+h.getName()+","+h.getFunctionApplied();
			//mapiline+=","+h.getChecksumBehavior();
		}
		
		Vector params=h.getFunctionParameters();
		if(params.size()==0) {
		}
		else {
			if(h.getFunctionApplied().equals("STRIP")) {
				mapiline+=","+((String)params.elementAt(0));
			}
			else if(h.getFunctionApplied().equals("PATTERN_FILL")) {
				mapiline+=","+((String)params.elementAt(0))+",";
				if(((String)params.elementAt(0)).equals("STR")) 
					mapiline+="\""+((String)params.elementAt(1))+"\"";
				else
					mapiline+=((String)params.elementAt(1));
			}
			else if(h.getFunctionApplied().equals("REPLACE")) {
				mapiline+=",\""+((String)params.elementAt(0))+"\"";
			}
			else if(h.getFunctionApplied().equals("HASHED")) {
				mapiline+=","+((String)params.elementAt(0));
			}
			else if(h.getFunctionApplied().equals("MAP_DISTRIBUTION")) {
				mapiline+=","+((String)params.elementAt(0))+","+((String)params.elementAt(1))+","+((String)params.elementAt(2));
			}
			else if(h.getFunctionApplied().equals("REGEX")) {
				mapiline+=",\""+((String)params.elementAt(0))+"\"";
				mapiline+=",\""+((String)params.elementAt(1))+"\"";
			}
		}
		mapiline+=");";
		return mapiline;

	}

	public String mapiprocessFields(Vector v,boolean commentLines) {
		String code="";
		
		for(int k=0;k<v.size();k++) {
			HeaderField h=(HeaderField)v.elementAt(k);
			if(!h.getFunctionApplied().equals("UNCHANGED")) {
				if(commentLines)
					code+="<font color=gray>#"+createMapiCodeFromField(h,false)+"</font><br>";
				else
					code+=createMapiCodeFromField(h,true)+"<br>";
			}
		}
		return code;
	}
	
	public String createMapiCode(boolean commentLines,boolean setHTMLHeaders) {
		String code="";
		
		if(setHTMLHeaders)
			code="<html><head></head><body>";
		
	
		String intrncode="";
		Vector ipfields=ipHeaderPanel.getFields();
		intrncode+=mapiprocessFields(ipfields,commentLines);
		Vector tcpfields=tcpHeaderPanel.getFields();
		intrncode+=mapiprocessFields(tcpfields,commentLines);
		Vector udpfields=udpHeaderPanel.getFields();
		intrncode+=mapiprocessFields(udpfields,commentLines);
		Vector icmpfields=icmpHeaderPanel.getFields();
		intrncode+=mapiprocessFields(icmpfields,commentLines);
		Vector httpfields=httpHeaderPanel.getFields();
		intrncode+=mapiprocessFields(httpfields,commentLines);
		Vector ftpfields=ftpHeaderPanel.getFields();
		intrncode+=mapiprocessFields(ftpfields,commentLines);
		
		if((!intrncode.equals("")) && enforcedFunctions!=null) {
			System.out.print(enforcedFunctions.size()+"\n");
			for(int jj=0;jj<enforcedFunctions.size();jj+=3) {
				String fname=(String)enforcedFunctions.elementAt(jj);
				String mapiline="";
				if(commentLines) { 
					mapiline="<font color=gray>#mapi_apply_function(fd,\""+fname+"\"";
				}
				else { 
					mapiline="<strong>mapi_apply_function</strong>(<em>fd</em>,<strong><font color=red>\""+fname+"\"</font></strong>";
				}
				String param1=(String)enforcedFunctions.elementAt(jj+1);
				String param2=(String)enforcedFunctions.elementAt(jj+2);

				if(!param1.equals("")) {
					mapiline+=",\""+param1+"\"";
				}
				
				if(!param2.equals("")) {
					mapiline+=",\""+param2+"\"";
				}
				mapiline+=");";
				if(commentLines)
					mapiline+="</font>";
				mapiline+="<br>";
				code+=mapiline;
			}
		}
		
		if(cookingApplied==true) {
			if(commentLines) { 
				code+="<font color=gray>#mapi_apply_function(fd,\"COOKING\",500000,10); </font><br>";
			}
			else { 
				code+="<strong>mapi_apply_function</strong>(<em>fd</em>,<strong><font color=red>\"COOKING\"</font></strong>,500000,10);<br>";
			}
		}

		code+=intrncode;
		if(uncookApplied==true) {
			if(commentLines) { 
				code+="<font color=gray>#mapi_apply_function(fd,\"UNCOOK\"); </font><br>";
			}
			else { 
				code+="<strong>mapi_apply_function</strong>(<em>fd</em>,<strong><font color=red>\"UNCOOK\"</font></strong>);<br>";
			}
		}
		
		if(setHTMLHeaders)
			code+="</body></html>";
		
		if(code.equals("<html><head></head><body></body></html>"))
			return new String("");
		return code;
	}
	
	int fno=0;
	
	public String keynoteprocessFields(Vector v) {
		String code="";
			
		for(int k=0;k<v.size();k++) {
			HeaderField h=(HeaderField)v.elementAt(k);
			if(!h.getFunctionApplied().equals("UNCHANGED")) {
				code+="<font color=green>ANONYMIZE."+fno+".param.0 </font> == "+h.getProtocol()+" && <br>";
				code+="<font color=green>ANONYMIZE."+fno+".param.1 </font> == "+h.getName()+" && <br>";
				code+="<font color=green>ANONYMIZE."+fno+".param.2 </font> == "+h.getFunctionApplied();
				if(h.getFunctionParameters().size()>0) 
					code+=" && <br>";
				//code+="<br>";	
								
				if(h.getFunctionApplied().equals("HASHED")) {
					Vector params=h.getFunctionParameters();
					code+="(";
					int s=params.size();
					for(int f=0;f<s;f++) {
						if(f<(s-1)) 
							code+="<font color=green>ANONYMIZE."+fno+".param.3</font> == "+((String)params.elementAt(f))+"|| <br>";
						else
							code+="<font color=green>ANONYMIZE."+fno+".param.3</font> == "+((String)params.elementAt(f))+") <br>";
					}
				}
				else if(h.getFunctionApplied().equals("PATTERN_FILL")) {
					code+="(";
					code+="(<font color=green>ANONYMIZE."+fno+".param.3</font> == "+((String)h.getFunctionParameters().elementAt(0))+" && <br>";
					code+="<font color=green>ANONYMIZE."+fno+".param.4</font> == "+((String)h.getFunctionParameters().elementAt(1))+")";
					if(h.getFunctionParameters().size()>2) {
						code+="||<br>";
						code+="(<font color=green>ANONYMIZE."+fno+".param.3</font> == "+((String)h.getFunctionParameters().elementAt(2))+" && <br>";
						code+="<font color=green>ANONYMIZE."+fno+".param.4</font> == "+((String)h.getFunctionParameters().elementAt(3))+")";
					}
					code+=") <br>";
				}
				else if(h.getFunctionApplied().equals("REGEX")) {
					Vector params=h.getFunctionParameters();
					code+="<font color=green>ANONYMIZE."+fno+".param.0</font> == \""+((String)params.elementAt(0))+"\" &&<br>";
					code+="<font color=green>ANONYMIZE."+fno+".param.1</font> == \""+((String)params.elementAt(1))+"\" <br>";
				}
				else if(h.getFunctionApplied().equals("STRIP") || h.getFunctionApplied().equals("REPLACE")) {
					Vector params=h.getFunctionParameters();
					code+="<font color=green>ANONYMIZE."+fno+".param.3</font> == "+((String)params.elementAt(0))+" <br>";
				}
				else if(h.getFunctionApplied().equals("MAP_DISTRIBUTION")) {
					code+="(";
		code+="(<font color=green>ANONYMIZE."+fno+".param.3</font> == "+((String)h.getFunctionParameters().elementAt(0))+" && <br>";
		code+="<font color=green>ANONYMIZE."+fno+".param.4</font> == "+((String)h.getFunctionParameters().elementAt(1))+" && <br>";
		code+="<font color=green>ANONYMIZE."+fno+".param.5</font> == "+((String)h.getFunctionParameters().elementAt(2))+") <br>";
		
					if(h.getFunctionParameters().size()>3) {
						code+="||";
		code+="(<font color=green>ANONYMIZE."+fno+".param.3</font> == "+((String)h.getFunctionParameters().elementAt(3))+" && <br>";
		code+="<font color=green>ANONYMIZE."+fno+".param.4</font> == "+((String)h.getFunctionParameters().elementAt(4))+" && <br>";
		code+="<font color=green>ANONYMIZE."+fno+".param.5</font> == "+((String)h.getFunctionParameters().elementAt(5))+")";
					}
					code+=") <br>";
				}

				for(int gg=k+1;gg<v.size();gg++) {
					try {
						HeaderField hh=(HeaderField)v.elementAt(gg);
						if(!hh.getFunctionApplied().equals("UNCHANGED")) {
							code+=" &&<br>";
							break;
						}
					}
					catch(Exception qq) {
						break;
					}
				}

				fno++;	
				
			}
		}
		return code;
	}

	
	public String createKeynoteCode(boolean appendMapiCode) {
		String code="<html><head></head><body>";

		String funccode="";
		fno=0;
		String[] partialCodes=new String[6];
		
		Vector ipfields=ipHeaderPanel.getFields();
		partialCodes[0]=keynoteprocessFields(ipfields);
		
		Vector tcpfields=tcpHeaderPanel.getFields();
		partialCodes[1]=keynoteprocessFields(tcpfields);
		
		Vector udpfields=udpHeaderPanel.getFields();
		partialCodes[2]=keynoteprocessFields(udpfields);
		
		Vector icmpfields=icmpHeaderPanel.getFields();
		partialCodes[3]=keynoteprocessFields(icmpfields);
		
		Vector httpfields=httpHeaderPanel.getFields();
		partialCodes[4]=keynoteprocessFields(httpfields);
		
		Vector ftpfields=ftpHeaderPanel.getFields();
		partialCodes[5]=keynoteprocessFields(ftpfields);
	
		for(int ff=0;ff<6;ff++) {
			if(!partialCodes[ff].equals("")) {
				funccode+=partialCodes[ff];
				for(int rr=ff+1;rr<6;rr++) {
					if(!partialCodes[rr].equals("")) {
						funccode+=" && <br>";
						break;
					}
				}
			}
		}
		
		
		if(funccode.equals("")) 
			return funccode;

		code+="<strong><font color=	#A52A2A>Authorizer: </font></strong> \"RSA:abc123\"<br>";
		code+="<strong><font color=	#A52A2A>Licensees: </font></strong> \"RSA:xyz123\"<br>";
		code+="<strong><font color=	#A52A2A>Conditions: </font></strong> (<font color=green>device_name</font> ~= \"eth[0-9]\") && (<br> ";

		int fcount=0;

		if(deletedFuncs!=null && deletedFuncs.size()>0) {
			for(int f=0;f<deletedFuncs.size();f++) {
				code+="<font color=green>"+(String)(deletedFuncs.elementAt(f))+"</font> == \"not defined\" && <br>";
			}
		}
		
		if(cookingApplied) {
			code+="<font color=green>COOKING.0.pos == </font>(ANONYMIZE.0.pos-1) && <br>";
			fcount++;
		}
	
		String realcode="";
		if(enforcedFunctions!=null) {
			for(int jj=0;jj<enforcedFunctions.size();jj+=3) {
				String fname=(String)enforcedFunctions.elementAt(jj);
				int prev_cnt=0;
				for(int kk=0;kk<jj;kk++) {
					if(((String)enforcedFunctions.elementAt(kk)).equals(fname)) {
						prev_cnt++;
					}
				}
				realcode+="<font color=green>"+fname+"."+prev_cnt+".pos &lt; </font>";
				if(jj<(enforcedFunctions.size()-3))  {
					String nextfunc=(String)enforcedFunctions.elementAt(jj+3);
					int prev_cnt2=0;
					for(int ll=0;ll<(jj+3);ll++) {
						if(((String)enforcedFunctions.elementAt(ll)).equals(nextfunc)) {
							prev_cnt2++;
						}
					}
					realcode+=nextfunc+"."+prev_cnt2+".pos";
				}
				else {
					realcode+="ANONYMIZE.0.pos";
				}
				realcode+=" && <br>";
				String param1=(String)enforcedFunctions.elementAt(jj+1);
				String param2=(String)enforcedFunctions.elementAt(jj+2);

				if(!param1.equals("")) {
					realcode+="<font color=green>"+fname+"."+prev_cnt+".param.0==</font>\""+param1+"\" && <br>";
				}
				
				if(!param2.equals("")) {
					realcode+="<font color=green>"+fname+"."+prev_cnt+".param.1==</font>\""+param2+"\" && <br>";
				}
				
				fcount++;
			}
		}
		
		realcode+=funccode;
		
		
			
		if(allowedFuncsBeforeAnon.size()>0) {
			code+="(";
			code+="("+(String)allowedFuncsBeforeAnon.elementAt(0)+".0.pos &lt; ANONYMIZE.0.pos && <br>"+ realcode +")<br>";
			code+=" || ("+realcode+") <br>";
			code+=") &&<br>";
		}
		else {
			code+=realcode;
		}

		if(allowedFuncsBeforeAnon.size()==0) 
			code+=" &&<br>";
			
		if(uncookApplied==true) {
			code+="<font color=green>UNCOOK.0.pos</font> == (ANONYMIZE.last.pos+1) && <br>";
		}
	
		
		code+=" <font color=green>app_domain</font>== MAPI";
		code+=")<br>";
		code+="<strong><font color=	#A52A2A>Signature: </font></strong> \"RSA-SHA1: 233345ff9\"";
		
		if(appendMapiCode) {
			code+="<br>"+createMapiCode(true,false);
		}

		code+="</body></html>";
		return code;
	}

	public void applyCooking() {
		if(cookingApplied==false)
			cookingApplied=true;
		else
			cookingApplied=false;
	}
	
	public void applyUnCook() {
		if(uncookApplied==false)
			uncookApplied=true;
		else	
			uncookApplied=false;
	}

	public void allowFuncBeforeCooking(Vector v) {
		this.allowedFuncsBeforeAnon=v;
	}

	public void setEnforceFuncs(Vector v) {
		this.enforcedFunctions=v;
	}

	public Vector getEnforceFuncs() {
		return this.enforcedFunctions;
	}

	public Vector getAllowedFuncs() {
		return this.allowedFuncsBeforeAnon;
	}
	
	public Vector getDeletedFuncs() {
		return this.deletedFuncs;
	}

	public void deleteFuncs(Vector v) {
		this.deletedFuncs=v;
	}
}


class SplashWindow extends JWindow
{
    public SplashWindow(String filename,JFrame f, int waitTime)
    {
        JLabel l = new JLabel(new ImageIcon(filename));
        getContentPane().add(l, BorderLayout.CENTER);
        pack();
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        Dimension labelSize = l.getPreferredSize();
        setLocation(screenSize.width/2 - (labelSize.width/2),screenSize.height/2 - (labelSize.height/2));
        final int pause = waitTime;
        final JFrame fr= f;

        Runnable waitRunner = new Runnable() {
                public void run()
                {
                    try
                        {
                            Thread.sleep(pause);
                    		setVisible(false);
                    		dispose();
							fr.setVisible(true);
                        }
                    catch(Exception e)
                        {
							fr.setVisible(true);
                        }
                }
            };

        setVisible(true);
        Thread splashThread = new Thread(waitRunner, "SplashThread");
        splashThread.start();
    }
}

public class AnonymizePolicyGUI implements ActionListener{
	Vector functionsVector;
	ProtocolGroup defaultPolicy;
	JTabbedPane tabbedPane;
	JFrame frame;
	Vector groups;
	String[] mapiFuncNames;
	JMenuItem ip_menuitem,tcp_menuitem,udp_menuitem,icmp_menuitem,http_menuitem,ftp_menuitem;
	boolean demoMode=false;

	public void loadFunctions(String filename) {
		try {
			BufferedReader br = new BufferedReader( new FileReader(filename) );
			String line = null;
			while((line=br.readLine())!=null) {
				if(line.charAt(0)=='#') 
					continue;
				functionsVector.add(new AnonymizeFunction(line));
			}
		}catch(Exception e) {
			System.out.print("Exception:"+e.getMessage());
			System.exit(0);
		}
	}

	public AnonymizePolicyGUI() {
		 mapiFuncNames=new String[]{"BPF_FILTER","BUCKET","BYTE_COUNTER","DIST","ETHEREAL","GAP","HASHSAMP","HASH",
		"PKTINFO","PKT_COUNTER","RES2FILE","SAMPLE","STATS","STR_SEARCH","TO_BUFFER","TO_FILE","THRESHOLD"};

		functionsVector=new Vector();
		loadFunctions("./functions.txt");
		groups=new Vector();
		drawGUI();
	}
		
	JFrame codeframe;	
	JEditorPane codetextarea;
	JFrame allowframe,deleteframe;
	JList flist;
	JFrame donotapplyframe;
	JComboBox[] enforcecmb;
	JTextField[] enfparameter1;
	JTextField[] enfparameter2;  
	JFrame enforceframe;

	public void showCode(String code,String title) {
		
		codeframe = new JFrame(title);

		if(code.equals("")) {
			codetextarea=new JEditorPane("text/html","<h3>No fields were changed. No code to display</h3>");	
		}
		else {
			codetextarea=new JEditorPane("text/html",code);
		}
		codetextarea.setEditable(false);
		JScrollPane scrollableTextArea = new JScrollPane(codetextarea);

		JPanel panel=new JPanel(new BorderLayout());
		panel.add(scrollableTextArea,BorderLayout.CENTER);
		
		JPanel controlpanel=new JPanel(new GridLayout(1,4));
		controlpanel.add(new JLabel(""));
		
		JButton codecopy=new JButton("Copy to clipboard");
		codecopy.addActionListener(this);
		codecopy.setActionCommand("codecopy");
		controlpanel.add(codecopy);

		JButton codesave=new JButton("Save to file");
		codesave.addActionListener(this);
		codesave.setActionCommand("codesave");
		if(code.equals("")) {
			codecopy.setEnabled(false);
			codesave.setEnabled(false);
		}

		controlpanel.add(codesave);
		JButton codeclose=new JButton("Close");
		codeclose.addActionListener(this);
		codeclose.setActionCommand("codeclose");

		controlpanel.add(codeclose);	
		panel.add(controlpanel,BorderLayout.SOUTH);

		codeframe.getContentPane().add(panel);
		codeframe.pack();
		codeframe.setSize(700,500);
		codeframe.show();
	}

	public void savePolicy(ProtocolGroup grp) {	
			JFileChooser fc=new JFileChooser();
			int option=fc.showSaveDialog(frame);
			File file = fc.getSelectedFile();
			try {
				FileOutputStream out;
				PrintStream p;
				out = new FileOutputStream(file);
				p = new PrintStream( out );

				Vector[] vectors={grp.getIPHeader().getFields(),grp.getTCPHeader().getFields(),grp.getUDPHeader().getFields(),
				grp.getICMPHeader().getFields(),grp.getHTTPHeader().getFields(),grp.getFTPHeader().getFields()};
				
				for(int v=0;v<vectors.length;v++) {
					for(int i=0;i<vectors[v].size();i++) {
						HeaderField h=(HeaderField)vectors[v].elementAt(i);
						if(!h.getFunctionApplied().equals("UNCHANGED")) {
							p.print("FIELD "+h.getProtocol()+" "+h.getName()+" "+h.getFunctionApplied()+" ");
							Vector params=h.getFunctionParameters();
							for(int f=0;f<params.size();f++) {
								p.print((String)params.elementAt(f)+" ");
							}
							p.println("");
						}
					
					}
				}

				Vector deleted=grp.getDeletedFuncs();
				if(deleted!=null) {
					for(int k=0;k<deleted.size();k++) {
						p.println("DELETE "+(String)deleted.elementAt(k));
					}
				}
				
				Vector allowed=grp.getAllowedFuncs();
				if(allowed!=null) {
					for(int k=0;k<allowed.size();k++) {
						p.println("ALLOW "+(String)allowed.elementAt(k));
					}
				}
				
				Vector enforced=grp.getEnforceFuncs();
				if(enforced!=null) {
					for(int k=0;k<enforced.size();k+=3) {
						p.println("ENFORCE "+(String)enforced.elementAt(k)+" "+(String)enforced.elementAt(k+1)+" "+(String)enforced.elementAt(k+2));
					}
				}

				
				out.close();
				p.close();
					
			}
			catch(Exception e) {
				System.out.println("");
				e.printStackTrace();
			}
	}

	public void handleQuit() {
			for(int f=0;f<groups.size();f++) {
				String mcode=((ProtocolGroup)groups.elementAt(f)).createMapiCode(false,true);
				if(!mcode.equals("")) {
					int tosave=JOptionPane.showConfirmDialog(frame,"Do you want to save policy for \""+tabbedPane.getTitleAt(f)+"\"?","Save Policy?",JOptionPane.YES_NO_OPTION,JOptionPane.QUESTION_MESSAGE);
					if(tosave==JOptionPane.YES_OPTION) {
						savePolicy((ProtocolGroup)groups.elementAt(f));
					}
				}
			}
			
			System.exit(0);
	}

	public void resetProtocolMenuITemIcons() {
		ip_menuitem.setIcon(null);
		tcp_menuitem.setIcon(null);
		udp_menuitem.setIcon(null);
		icmp_menuitem.setIcon(null);
		http_menuitem.setIcon(null);
		ftp_menuitem.setIcon(null);
	}

	public void actionPerformed(ActionEvent e) {
		String command=e.getActionCommand();
		
		if(command.equals("quit")) {
			handleQuit();	
		}
		else if(command.equals("savepolicy")) {
			savePolicy((ProtocolGroup)groups.elementAt(tabbedPane.getSelectedIndex()));
		}
		else if(command.equals("codesave")) {
			codetextarea.selectAll();
			String lala=codetextarea.getSelectedText();
			codetextarea.select(0,0);
			
			JFileChooser fc=new JFileChooser();
			int option=fc.showSaveDialog(frame);
			File file = fc.getSelectedFile();
            //file.getName()
		}
		else if(command.equals("codeclose")) {
			codeframe.dispose();
		}
		else if(command.equals("codecopy")) {
			codetextarea.selectAll();
			codetextarea.copy();
			codetextarea.select(0,0);
		}
		else if(command.equals("mapicode")) {
			showCode( ((ProtocolGroup)groups.elementAt(tabbedPane.getSelectedIndex())).createMapiCode(false,true),"MAPI code");
		}
		else if(command.equals("keynotecode")) {
			showCode( ((ProtocolGroup)groups.elementAt(tabbedPane.getSelectedIndex())).createKeynoteCode(false),"Keynote Code");
		}
		else if(command.equals("keynotemapicode")) {
			showCode( ((ProtocolGroup)groups.elementAt(tabbedPane.getSelectedIndex())).createKeynoteCode(true),"Keynote code with MAPI code appended");
		}
		else if(command.equals("newpolicy")) {
			String s = (String)JOptionPane.showInputDialog(
                    frame,
                    "Name ff the new policy",
                    "New policy",
                    JOptionPane.PLAIN_MESSAGE,
                    null,
                    null,
                    "New policy");
			if(s==null || s.equals("")) 
				s=new String("Unnamed");
			ProtocolGroup grp=new ProtocolGroup(s,functionsVector,frame);
			groups.add(grp);
			tabbedPane.addTab(s, null,grp.getIPHeader(),"Policy for"+s);
			tabbedPane.setSelectedIndex(groups.size()-1);
		}
		else if(command.equals("IP")) {
			int index=tabbedPane.getSelectedIndex();
			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(index);
			IPHeaderPanel ippanel=grp.getIPHeader();
			
			tabbedPane.removeTabAt(index);
			tabbedPane.insertTab(grp.getName(),null,ippanel,"tip",index);
			tabbedPane.setSelectedIndex(index);

			frame.setSize(ippanel.getPanelSize());
			frame.pack();
			
			resetProtocolMenuITemIcons();
			ip_menuitem.setIcon(new ImageIcon("tick.gif"));
		}
		else if(command.equals("UDP")) {
			int index=tabbedPane.getSelectedIndex();
			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(index);
			UDPHeaderPanel udppanel=grp.getUDPHeader();
			
			tabbedPane.removeTabAt(index);
			tabbedPane.insertTab(grp.getName(),null,udppanel,"tip",index);
			tabbedPane.setSelectedIndex(index);

			frame.setSize(udppanel.getPanelSize());
			frame.pack();
			
			resetProtocolMenuITemIcons();
			udp_menuitem.setIcon(new ImageIcon("tick.gif"));

		}
		else if(command.equals("TCP")) {
			int index=tabbedPane.getSelectedIndex();
			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(index);
			TCPHeaderPanel tcppanel=grp.getTCPHeader();
			
			tabbedPane.removeTabAt(index);
			tabbedPane.insertTab(grp.getName(),null,tcppanel,"tip",index);
			tabbedPane.setSelectedIndex(index);
			
			frame.setSize(tcppanel.getPanelSize());
			frame.pack();
			resetProtocolMenuITemIcons();
			tcp_menuitem.setIcon(new ImageIcon("tick.gif"));
			
		}
		else if(command.equals("ICMP")) {
			int index=tabbedPane.getSelectedIndex();
			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(index);
			ICMPHeaderPanel icmppanel=grp.getICMPHeader();
			
			tabbedPane.removeTabAt(index);
			tabbedPane.insertTab(grp.getName(),null,icmppanel,"tip",index);
			tabbedPane.setSelectedIndex(index);
			
			frame.setSize(icmppanel.getPanelSize());
			frame.pack();
			resetProtocolMenuITemIcons();
			icmp_menuitem.setIcon(new ImageIcon("tick.gif"));
		}
		else if(command.equals("HTTP")) {
			int index=tabbedPane.getSelectedIndex();
			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(index);
			HTTPHeaderPanel httppanel=grp.getHTTPHeader();
			
			tabbedPane.removeTabAt(index);
			tabbedPane.insertTab(grp.getName(),null,httppanel,"tip",index);
			tabbedPane.setSelectedIndex(index);

			frame.setSize(httppanel.getPanelSize());
			frame.pack();
			resetProtocolMenuITemIcons();
			http_menuitem.setIcon(new ImageIcon("tick.gif"));
			
		}
		else if(command.equals("FTP")) {
			int index=tabbedPane.getSelectedIndex();
			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(index);
			FTPHeaderPanel ftppanel=grp.getFTPHeader();
			
			tabbedPane.removeTabAt(index);
			tabbedPane.insertTab(grp.getName(),null,ftppanel,"tip",index);
			tabbedPane.setSelectedIndex(index);

			frame.setSize(ftppanel.getPanelSize());
			frame.pack();
			resetProtocolMenuITemIcons();
			ftp_menuitem.setIcon(new ImageIcon("tick.gif"));
		}
		else if(command.equals("applybefore")) {
			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(tabbedPane.getSelectedIndex());
			grp.applyCooking();
		}
		else if(command.equals("uncookafter")) {
			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(tabbedPane.getSelectedIndex());
			grp.applyUnCook();
		}
		else if(command.equals("deletefuncs")) {
			deleteframe=new JFrame("Allow functions before anonymization");

			deleteframe.addWindowListener(new WindowAdapter() {
        	  public void windowClosing(WindowEvent e) {
        	     frame.setEnabled(true);
        	  }
        	});
	
			JPanel deletepanel=new JPanel(new BorderLayout());
			deletepanel.add(new JLabel("Specify which functions can be used before anonymization"), BorderLayout.NORTH);
	
			flist = new JList(mapiFuncNames); //data has type Object[]
			flist.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
			flist.setLayoutOrientation(JList.VERTICAL);
			flist.setVisibleRowCount(-1);
			deletepanel.add(flist,BorderLayout.CENTER);

			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(tabbedPane.getSelectedIndex());
			Vector retrDelete=grp.getDeletedFuncs();
			if(retrDelete!=null) {
				int[] indices=new int[retrDelete.size()];
 				int ind_cnt=0;
				
				for(int aa=0;aa<retrDelete.size();aa++) {
					String allname=(String)retrDelete.elementAt(aa);
					for(int ii = 0; ii < flist.getModel().getSize(); ii++) {
					     if(flist.getModel().getElementAt(ii).equals(allname)) {
							 indices[ind_cnt]=ii;
							 ind_cnt++;
						 }
 					}
				}
				
				flist.setSelectedIndices(indices);
			}

			JPanel okcancelpanel=new JPanel(new GridLayout(1,3));
			okcancelpanel.add(new JLabel(""));
			JButton deletecancel=new JButton("Cancel");
			deletecancel.setActionCommand("deletecancel");
			deletecancel.addActionListener(this);
			okcancelpanel.add(deletecancel);
			
			JButton deleteok=new JButton("OK");
			deleteok.setActionCommand("deleteok");
			deleteok.addActionListener(this);
			okcancelpanel.add(deleteok);
			
			deletepanel.add(okcancelpanel,BorderLayout.SOUTH);
			
			frame.setEnabled(false);
			deleteframe.getContentPane().add(deletepanel);
			deleteframe.pack();
			deleteframe.setVisible(true);
		}	
		else if(command.equals("deletecancel")) {
			frame.setEnabled(true);
			deleteframe.dispose();
		}
		else if(command.equals("deleteok")) {
			int[] indices=flist.getSelectedIndices();
			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(tabbedPane.getSelectedIndex());
			Vector v=new Vector();
			
			for(int g=0;g<indices.length;g++) {
				v.add(mapiFuncNames[indices[g]]);
			}
			
			grp.deleteFuncs(v);
			frame.setEnabled(true);
			deleteframe.dispose();
		}
		else if(command.equals("allowfuncs")) {
			allowframe=new JFrame("Allow functions before anonymization");

			allowframe.addWindowListener(new WindowAdapter() {
        	  public void windowClosing(WindowEvent e) {
        	     frame.setEnabled(true);
        	  }
        	});
	
			JPanel allowpanel=new JPanel(new BorderLayout());
			allowpanel.add(new JLabel("Specify which functions can be used before anonymization"), BorderLayout.NORTH);
	
			flist = new JList(mapiFuncNames); //data has type Object[]
			flist.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
			flist.setLayoutOrientation(JList.VERTICAL);
			flist.setVisibleRowCount(-1);
			allowpanel.add(flist,BorderLayout.CENTER);

			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(tabbedPane.getSelectedIndex());
			Vector retrAllow=grp.getAllowedFuncs();
			if(retrAllow!=null) {
				int[] indices=new int[retrAllow.size()];
 				int ind_cnt=0;
				
				for(int aa=0;aa<retrAllow.size();aa++) {
					String allname=(String)retrAllow.elementAt(aa);
					for(int ii = 0; ii < flist.getModel().getSize(); ii++) {
					     if(flist.getModel().getElementAt(ii).equals(allname)) {
							 indices[ind_cnt]=ii;
							 ind_cnt++;
						 }
 					}
				}
				
				flist.setSelectedIndices(indices);
			}

			JPanel okcancelpanel=new JPanel(new GridLayout(1,3));
			okcancelpanel.add(new JLabel(""));
			JButton allowcancel=new JButton("Cancel");
			allowcancel.setActionCommand("allowcancel");
			allowcancel.addActionListener(this);
			okcancelpanel.add(allowcancel);
			
			JButton allowok=new JButton("OK");
			allowok.setActionCommand("allowok");
			allowok.addActionListener(this);
			okcancelpanel.add(allowok);
			
			allowpanel.add(okcancelpanel,BorderLayout.SOUTH);
			
			frame.setEnabled(false);
			allowframe.getContentPane().add(allowpanel);
			allowframe.pack();
			allowframe.setVisible(true);
		}
		else if(command.equals("allowcancel")) {
			frame.setEnabled(true);
			allowframe.dispose();
		}
		else if(command.equals("allowok")) {
			int[] indices=flist.getSelectedIndices();
			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(tabbedPane.getSelectedIndex());
			Vector v=new Vector();
			
			for(int g=0;g<indices.length;g++) {
				v.add(mapiFuncNames[indices[g]]);
			}
			
			grp.allowFuncBeforeCooking(v);
			frame.setEnabled(true);
			allowframe.dispose();
		}
		else if(command.equals("donotapply")) {
			donotapplyframe=new JFrame("Do not apply anonymization if...");

			donotapplyframe.addWindowListener(new WindowAdapter() {
        	  public void windowClosing(WindowEvent e) {
        	     frame.setEnabled(true);
        	  }
        	});
	
			JPanel donotapplypanel=new JPanel(new BorderLayout());
			JPanel labelpanel=new JPanel(new GridLayout(2,1));
			labelpanel.add(new JLabel("If the flow contains only the functions selected below"));
			labelpanel.add(new JLabel("then there is no need for anonymization"));
			
			donotapplypanel.add(labelpanel, BorderLayout.NORTH);
			
			flist = new JList(mapiFuncNames); //data has type Object[]
			flist.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
			flist.setLayoutOrientation(JList.VERTICAL);
			flist.setVisibleRowCount(-1);
			donotapplypanel.add(flist,BorderLayout.CENTER);

				
			JPanel okcancelpanel=new JPanel(new GridLayout(1,3));
			okcancelpanel.add(new JLabel(""));
			JButton donotapplycancel=new JButton("Cancel");
			donotapplycancel.setActionCommand("donotapplycancel");
			donotapplycancel.addActionListener(this);
			okcancelpanel.add(donotapplycancel);
			
			JButton donotapplyok=new JButton("OK");
			donotapplyok.setActionCommand("donotapplyok");
			donotapplyok.addActionListener(this);
			okcancelpanel.add(donotapplyok);
			
			donotapplypanel.add(okcancelpanel,BorderLayout.SOUTH);
			
			frame.setEnabled(false);
			donotapplyframe.getContentPane().add(donotapplypanel);
			donotapplyframe.pack();
			donotapplyframe.setVisible(true);	
		}
		else if(command.equals("donotapplycancel")) {
			frame.setEnabled(true);
			donotapplyframe.dispose();
		}
		else if(command.equals("donotapplyok")) {
			int[] indices=flist.getSelectedIndices();
			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(tabbedPane.getSelectedIndex());

			for(int g=0;g<indices.length;g++) {
				System.out.println(mapiFuncNames[indices[g]]);
				//grp.allowFuncBeforeCooking(mapiFuncNames[indices[g]]);
			}
			
			frame.setEnabled(true);
			donotapplyframe.dispose();
		}
		else if(command.equals("enforcefuncs")) {
			enforceframe=new JFrame("Enforce Functions before Anonymization");

			enforceframe.addWindowListener(new WindowAdapter() {
        	  public void windowClosing(WindowEvent e) {
        	     frame.setEnabled(true);
        	  }
        	});

			JPanel enforcepanel=new JPanel(new GridLayout(12,3));
			enforcepanel.add(new JLabel("Function Name"));
			enforcepanel.add(new JLabel("1st parameter"));
			enforcepanel.add(new JLabel("2nd parameter"));

			enforcecmb=new JComboBox[10];
			enfparameter1=new JTextField[10];
			enfparameter2=new JTextField[10];
			
			String[] str=new String[mapiFuncNames.length+1];
			str[0]="NONE";
			for(int gg=0;gg<mapiFuncNames.length;gg++) 
				str[gg+1]=new String(mapiFuncNames[gg]);
			
			
			for(int k=0;k<10;k++) {
				enforcecmb[k]=new JComboBox(str);
				enforcepanel.add(enforcecmb[k]);
				enfparameter1[k]=new JTextField(10);
				enforcepanel.add(enfparameter1[k]);
				enfparameter2[k]=new JTextField(10);
				enforcepanel.add(enfparameter2[k]);
			}
			
			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(tabbedPane.getSelectedIndex());
			Vector retrEnf=grp.getEnforceFuncs();

			if(retrEnf!=null) {
				for(int ff=0;ff<retrEnf.size();ff+=3) {
					String ffname=(String)retrEnf.elementAt(ff);
					int dd=0;
					for(dd=0;dd<mapiFuncNames.length;dd++) {
						if(ffname.equals(mapiFuncNames[dd]))
							break;
					}
					enforcecmb[ff/3].setSelectedIndex(dd+1);
					enfparameter1[ff/3].setText((String)retrEnf.elementAt(ff+1));
					enfparameter2[ff/3].setText((String)retrEnf.elementAt(ff+2));
				}
			}
			
			enforcepanel.add(new JLabel(""));
			JButton enforcecancel=new JButton("Cancel");
			enforcecancel.setActionCommand("enforcecancel");
			enforcecancel.addActionListener(this);
			enforcepanel.add(enforcecancel);
			JButton enforceok=new JButton("OK");
			enforceok.setActionCommand("enforceok");
			enforceok.addActionListener(this);
			enforcepanel.add(enforceok);

			
			enforceframe.getContentPane().add(enforcepanel);
			frame.setEnabled(false);
			enforceframe.pack();
			enforceframe.setVisible(true);
		}
		else if(command.equals("enforcecancel")) {
			frame.setEnabled(true);
			enforceframe.dispose();
		}
		else if(command.equals("enforceok")) {
			ProtocolGroup grp=(ProtocolGroup)groups.elementAt(tabbedPane.getSelectedIndex());
			Vector enfvec=new Vector();
			
			for(int i=0;i<10;i++) {
				String val=(String)(enforcecmb[i].getSelectedItem());
				if(!val.equals("NONE")) {
					enfvec.add(new String((String)(enforcecmb[i].getSelectedItem())));
					enfvec.add(new String(enfparameter1[i].getText()));
					enfvec.add(new String(enfparameter2[i].getText()));
				}
			}
		
			grp.setEnforceFuncs(enfvec);

			frame.setEnabled(true);
			enforceframe.dispose();
		}
		
	}

	Color defaultcolor;
	
	public void createToolbar(JFrame frame) {
		JMenuBar menubar=new JMenuBar();
		
		JMenu file=new JMenu("File");
		JMenuItem quit=new JMenuItem("Quit");
		quit.setActionCommand("quit");
		quit.addActionListener(this);
		JMenuItem newpolicy=new JMenuItem("New policy");
		newpolicy.setActionCommand("newpolicy");
		newpolicy.addActionListener(this);
		JMenuItem load=new JMenuItem("Load policy");
		JMenuItem save=new JMenuItem("Save policy");
		save.setActionCommand("savepolicy");
		save.addActionListener(this);
		file.add(newpolicy);
		file.add(load);
		file.add(save);
		file.addSeparator();
		file.add(quit);
		menubar.add(file);
		
		JMenu create=new JMenu("Create");
		JMenuItem keynotemapi=new JMenuItem("Keynote+MAPI code");
		keynotemapi.setActionCommand("keynotemapicode");
		keynotemapi.addActionListener(this);
		JMenuItem keynote=new JMenuItem("Keynote code");
		keynote.setActionCommand("keynotecode");
		keynote.addActionListener(this);
		JMenuItem mapi=new JMenuItem("MAPI code");
		mapi.setActionCommand("mapicode");
		mapi.addActionListener(this);
		create.add(keynotemapi);
		create.add(keynote);
		create.add(mapi);
		menubar.add(create);
	
	
		JMenu protocol=new JMenu("Protocol");
		ip_menuitem=new JMenuItem("IP",new ImageIcon("tick.gif"));
		defaultcolor=ip_menuitem.getBackground();
		ip_menuitem.addActionListener(this);
		ip_menuitem.setActionCommand("IP");
		
		tcp_menuitem=new JMenuItem("TCP");
		tcp_menuitem.addActionListener(this);
		tcp_menuitem.setActionCommand("TCP");
		
		udp_menuitem=new JMenuItem("UDP");
		udp_menuitem.addActionListener(this);
		udp_menuitem.setActionCommand("UDP");
		
		icmp_menuitem=new JMenuItem("ICMP");
		icmp_menuitem.addActionListener(this);
		icmp_menuitem.setActionCommand("ICMP");
		
		http_menuitem=new JMenuItem("HTTP");
		http_menuitem.addActionListener(this);
		http_menuitem.setActionCommand("HTTP");
		
		ftp_menuitem=new JMenuItem("FTP");
		ftp_menuitem.addActionListener(this);
		ftp_menuitem.setActionCommand("FTP");
		
		protocol.add(ip_menuitem);
		protocol.add(tcp_menuitem);
		protocol.add(udp_menuitem);
		protocol.add(icmp_menuitem);
		protocol.addSeparator();
		protocol.add(http_menuitem);
		protocol.add(ftp_menuitem);
		menubar.add(protocol);

		JMenu conditions=new JMenu("Conditions");
		
		JCheckBoxMenuItem cooking=new JCheckBoxMenuItem("Apply cooking before anonymization");
		cooking.setActionCommand("applybefore");
		cooking.addActionListener(this);
		conditions.add(cooking);

		JCheckBoxMenuItem uncook=new JCheckBoxMenuItem("Apply uncook after anonymization");
		uncook.setActionCommand("uncookafter");
		uncook.addActionListener(this);
		conditions.add(uncook);
		
		JMenuItem allowfuncs=new JMenuItem("Allow specific functions before anonymization");
		allowfuncs.setActionCommand("allowfuncs");
		allowfuncs.addActionListener(this);
		conditions.add(allowfuncs);
		
		JMenuItem enforcefuncs=new JMenuItem("Enforce specific functions before anonymization");
		enforcefuncs.setActionCommand("enforcefuncs");
		enforcefuncs.addActionListener(this);
		conditions.add(enforcefuncs);

		JMenuItem deletefuncs=new JMenuItem("Functions that cannot be applied at all");
		deletefuncs.setActionCommand("deletefuncs");
		deletefuncs.addActionListener(this);
		conditions.add(deletefuncs);
	
		JMenuItem donotapply=new JMenuItem("Do not perform anonymization if..");
		donotapply.setActionCommand("donotapply");
		donotapply.addActionListener(this);
		conditions.add(donotapply);
		menubar.add(conditions);

		JMenu help=new JMenu("Help");
		JMenuItem contents=new JMenuItem("Contents");
		JMenuItem about=new JMenuItem("About");
		help.add(contents);
		help.add(about);
		menubar.add(help);
	
		frame.setJMenuBar(menubar);
	}
	
	public void drawGUI() {
		JFrame.setDefaultLookAndFeelDecorated(true);
		Dimension screensize=Toolkit.getDefaultToolkit().getScreenSize();
        
		//Create and set up the window.
        frame = new JFrame("LOBSTER Anonymization Policy Maker");
		frame.addWindowListener(new WindowAdapter() {
          public void windowClosing(WindowEvent e) {
			  handleQuit();
          }
        });

		createToolbar(frame);
		
		defaultPolicy=new ProtocolGroup("Default",functionsVector,frame);
		groups.add(defaultPolicy);

		tabbedPane = new JTabbedPane();
		tabbedPane.addTab("Default", null,defaultPolicy.getIPHeader(),"Default policy");
		
		frame.getContentPane().add(tabbedPane);
        frame.pack();
	
		frame.setLocation(100,100);
		if(demoMode)
			new SplashWindow("lobster.jpg",frame,2000);
		else
        	frame.setVisible(true);
	}
	
	public static void main(String[] args) {
		new AnonymizePolicyGUI();
	}
}
