
pdf:
	echo "\begin{verbatim}" > man_mapi.tex
	man ./mapi.3 >> man_mapi.tex
	echo "\end{verbatim}" >> man_mapi.tex
	echo "\begin{verbatim}" > man_mapi_stdflib.tex
	man ./mapi_stdflib.3 >> man_mapi_stdflib.tex
	echo "\end{verbatim}" >> man_mapi_stdflib.tex
	echo "\begin{verbatim}" > man_mapi_dagflib.tex
	man ./mapi_dagflib.3 >> man_mapi_dagflib.tex
	echo "\end{verbatim}" >> man_mapi_dagflib.tex
	echo "\begin{verbatim}" > man_mapi_extraflib.tex
	man ./mapi_extraflib.3 >> man_mapi_extraflib.tex
	echo "\end{verbatim}" >> man_mapi_extraflib.tex
	echo "\begin{verbatim}" > man_mapi_trackflib.tex
	man ./mapi_trackflib.3 >> man_mapi_trackflib.tex
	echo "\end{verbatim}" >> man_mapi_trackflib.tex
	echo "\begin{verbatim}" > man_mapi_anonflib.tex
	man ./mapi_anonflib.3 >> man_mapi_anonflib.tex
	echo "\end{verbatim}" >> man_mapi_anonflib.tex
	latex mapitutor.tex
	latex mapitutor.tex
	dvipdf mapitutor.dvi

clean:
	rm -rf *.aux *.bbl *.blg *.log *.dvi *.toc *.lof mapitutor.ps *.bak man_mapi*tex


dist_man_MANS = mapi.3 mapi_stdflib.3 mapi_dagflib.3 mapi_extraflib.3 mapi_trackflib.3 mapi_anonflib.3 bpf2dagdsm.1 mapi_rulerflib.3 mapid.1 mapicommd.1

EXTRA_DIST = ipfixlib.txt \
	mapi_functions_tutorial.pdf \
	mapi_functions_tutorial.tex \
	mapitutor.pdf \
	mapitutor.tex \
	README_DIMAPI
