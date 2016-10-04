package android.support.v4.print;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Bitmap.Config;
import android.graphics.BitmapFactory;
import android.graphics.BitmapFactory.Options;
import android.graphics.Canvas;
import android.graphics.ColorMatrix;
import android.graphics.ColorMatrixColorFilter;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.pdf.PdfDocument.Page;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.CancellationSignal.OnCancelListener;
import android.os.ParcelFileDescriptor;
import android.print.PageRange;
import android.print.PrintAttributes;
import android.print.PrintAttributes.MediaSize;
import android.print.PrintDocumentAdapter;
import android.print.PrintDocumentAdapter.LayoutResultCallback;
import android.print.PrintDocumentAdapter.WriteResultCallback;
import android.print.PrintDocumentInfo;
import android.print.PrintDocumentInfo.Builder;
import android.print.PrintManager;
import android.print.pdf.PrintedPdfDocument;
import android.util.Log;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

class PrintHelperKitkat {
    public static final int COLOR_MODE_COLOR = 2;
    public static final int COLOR_MODE_MONOCHROME = 1;
    private static final String LOG_TAG = "PrintHelperKitkat";
    private static final int MAX_PRINT_SIZE = 3500;
    public static final int ORIENTATION_LANDSCAPE = 1;
    public static final int ORIENTATION_PORTRAIT = 2;
    public static final int SCALE_MODE_FILL = 2;
    public static final int SCALE_MODE_FIT = 1;
    int mColorMode;
    final Context mContext;
    Options mDecodeOptions;
    private final Object mLock;
    int mOrientation;
    int mScaleMode;

    /* renamed from: android.support.v4.print.PrintHelperKitkat.1 */
    class C00701 extends PrintDocumentAdapter {
        private PrintAttributes mAttributes;
        final /* synthetic */ Bitmap val$bitmap;
        final /* synthetic */ OnPrintFinishCallback val$callback;
        final /* synthetic */ int val$fittingMode;
        final /* synthetic */ String val$jobName;

        C00701(String str, Bitmap bitmap, int i, OnPrintFinishCallback onPrintFinishCallback) {
            this.val$jobName = str;
            this.val$bitmap = bitmap;
            this.val$fittingMode = i;
            this.val$callback = onPrintFinishCallback;
        }

        public void onLayout(PrintAttributes oldPrintAttributes, PrintAttributes newPrintAttributes, CancellationSignal cancellationSignal, LayoutResultCallback layoutResultCallback, Bundle bundle) {
            boolean changed = true;
            this.mAttributes = newPrintAttributes;
            PrintDocumentInfo info = new Builder(this.val$jobName).setContentType(PrintHelperKitkat.SCALE_MODE_FIT).setPageCount(PrintHelperKitkat.SCALE_MODE_FIT).build();
            if (newPrintAttributes.equals(oldPrintAttributes)) {
                changed = false;
            }
            layoutResultCallback.onLayoutFinished(info, changed);
        }

        public void onWrite(PageRange[] pageRanges, ParcelFileDescriptor fileDescriptor, CancellationSignal cancellationSignal, WriteResultCallback writeResultCallback) {
            PrintedPdfDocument pdfDocument = new PrintedPdfDocument(PrintHelperKitkat.this.mContext, this.mAttributes);
            Bitmap maybeGrayscale = PrintHelperKitkat.this.convertBitmapForColorMode(this.val$bitmap, this.mAttributes.getColorMode());
            try {
                Page page = pdfDocument.startPage(PrintHelperKitkat.SCALE_MODE_FIT);
                page.getCanvas().drawBitmap(maybeGrayscale, PrintHelperKitkat.this.getMatrix(maybeGrayscale.getWidth(), maybeGrayscale.getHeight(), new RectF(page.getInfo().getContentRect()), this.val$fittingMode), null);
                pdfDocument.finishPage(page);
                pdfDocument.writeTo(new FileOutputStream(fileDescriptor.getFileDescriptor()));
                PageRange[] pageRangeArr = new PageRange[PrintHelperKitkat.SCALE_MODE_FIT];
                pageRangeArr[0] = PageRange.ALL_PAGES;
                writeResultCallback.onWriteFinished(pageRangeArr);
            } catch (IOException ioe) {
                Log.e(PrintHelperKitkat.LOG_TAG, "Error writing printed content", ioe);
                writeResultCallback.onWriteFailed(null);
            } catch (Throwable th) {
                if (pdfDocument != null) {
                    pdfDocument.close();
                }
                if (fileDescriptor != null) {
                    try {
                        fileDescriptor.close();
                    } catch (IOException e) {
                    }
                }
                if (maybeGrayscale != this.val$bitmap) {
                    maybeGrayscale.recycle();
                }
            }
            if (pdfDocument != null) {
                pdfDocument.close();
            }
            if (fileDescriptor != null) {
                try {
                    fileDescriptor.close();
                } catch (IOException e2) {
                }
            }
            if (maybeGrayscale != this.val$bitmap) {
                maybeGrayscale.recycle();
            }
        }

        public void onFinish() {
            if (this.val$callback != null) {
                this.val$callback.onFinish();
            }
        }
    }

    /* renamed from: android.support.v4.print.PrintHelperKitkat.2 */
    class C00732 extends PrintDocumentAdapter {
        private PrintAttributes mAttributes;
        Bitmap mBitmap;
        AsyncTask<Uri, Boolean, Bitmap> mLoadBitmap;
        final /* synthetic */ OnPrintFinishCallback val$callback;
        final /* synthetic */ int val$fittingMode;
        final /* synthetic */ Uri val$imageFile;
        final /* synthetic */ String val$jobName;

        /* renamed from: android.support.v4.print.PrintHelperKitkat.2.1 */
        class C00721 extends AsyncTask<Uri, Boolean, Bitmap> {
            final /* synthetic */ CancellationSignal val$cancellationSignal;
            final /* synthetic */ LayoutResultCallback val$layoutResultCallback;
            final /* synthetic */ PrintAttributes val$newPrintAttributes;
            final /* synthetic */ PrintAttributes val$oldPrintAttributes;

            /* renamed from: android.support.v4.print.PrintHelperKitkat.2.1.1 */
            class C00711 implements OnCancelListener {
                C00711() {
                }

                public void onCancel() {
                    C00732.this.cancelLoad();
                    C00721.this.cancel(false);
                }
            }

            C00721(CancellationSignal cancellationSignal, PrintAttributes printAttributes, PrintAttributes printAttributes2, LayoutResultCallback layoutResultCallback) {
                this.val$cancellationSignal = cancellationSignal;
                this.val$newPrintAttributes = printAttributes;
                this.val$oldPrintAttributes = printAttributes2;
                this.val$layoutResultCallback = layoutResultCallback;
            }

            protected void onPreExecute() {
                this.val$cancellationSignal.setOnCancelListener(new C00711());
            }

            protected Bitmap doInBackground(Uri... uris) {
                try {
                    return PrintHelperKitkat.this.loadConstrainedBitmap(C00732.this.val$imageFile, PrintHelperKitkat.MAX_PRINT_SIZE);
                } catch (FileNotFoundException e) {
                    return null;
                }
            }

            protected void onPostExecute(Bitmap bitmap) {
                boolean changed = true;
                super.onPostExecute(bitmap);
                C00732.this.mBitmap = bitmap;
                if (bitmap != null) {
                    PrintDocumentInfo info = new Builder(C00732.this.val$jobName).setContentType(PrintHelperKitkat.SCALE_MODE_FIT).setPageCount(PrintHelperKitkat.SCALE_MODE_FIT).build();
                    if (this.val$newPrintAttributes.equals(this.val$oldPrintAttributes)) {
                        changed = false;
                    }
                    this.val$layoutResultCallback.onLayoutFinished(info, changed);
                } else {
                    this.val$layoutResultCallback.onLayoutFailed(null);
                }
                C00732.this.mLoadBitmap = null;
            }

            protected void onCancelled(Bitmap result) {
                this.val$layoutResultCallback.onLayoutCancelled();
                C00732.this.mLoadBitmap = null;
            }
        }

        C00732(String str, Uri uri, OnPrintFinishCallback onPrintFinishCallback, int i) {
            this.val$jobName = str;
            this.val$imageFile = uri;
            this.val$callback = onPrintFinishCallback;
            this.val$fittingMode = i;
            this.mBitmap = null;
        }

        public void onLayout(PrintAttributes oldPrintAttributes, PrintAttributes newPrintAttributes, CancellationSignal cancellationSignal, LayoutResultCallback layoutResultCallback, Bundle bundle) {
            boolean changed = true;
            this.mAttributes = newPrintAttributes;
            if (cancellationSignal.isCanceled()) {
                layoutResultCallback.onLayoutCancelled();
            } else if (this.mBitmap != null) {
                PrintDocumentInfo info = new Builder(this.val$jobName).setContentType(PrintHelperKitkat.SCALE_MODE_FIT).setPageCount(PrintHelperKitkat.SCALE_MODE_FIT).build();
                if (newPrintAttributes.equals(oldPrintAttributes)) {
                    changed = false;
                }
                layoutResultCallback.onLayoutFinished(info, changed);
            } else {
                this.mLoadBitmap = new C00721(cancellationSignal, newPrintAttributes, oldPrintAttributes, layoutResultCallback).execute(new Uri[0]);
            }
        }

        private void cancelLoad() {
            synchronized (PrintHelperKitkat.this.mLock) {
                if (PrintHelperKitkat.this.mDecodeOptions != null) {
                    PrintHelperKitkat.this.mDecodeOptions.requestCancelDecode();
                    PrintHelperKitkat.this.mDecodeOptions = null;
                }
            }
        }

        public void onFinish() {
            super.onFinish();
            cancelLoad();
            if (this.mLoadBitmap != null) {
                this.mLoadBitmap.cancel(true);
            }
            if (this.val$callback != null) {
                this.val$callback.onFinish();
            }
            if (this.mBitmap != null) {
                this.mBitmap.recycle();
                this.mBitmap = null;
            }
        }

        public void onWrite(PageRange[] pageRanges, ParcelFileDescriptor fileDescriptor, CancellationSignal cancellationSignal, WriteResultCallback writeResultCallback) {
            PrintedPdfDocument pdfDocument = new PrintedPdfDocument(PrintHelperKitkat.this.mContext, this.mAttributes);
            Bitmap maybeGrayscale = PrintHelperKitkat.this.convertBitmapForColorMode(this.mBitmap, this.mAttributes.getColorMode());
            try {
                Page page = pdfDocument.startPage(PrintHelperKitkat.SCALE_MODE_FIT);
                page.getCanvas().drawBitmap(maybeGrayscale, PrintHelperKitkat.this.getMatrix(this.mBitmap.getWidth(), this.mBitmap.getHeight(), new RectF(page.getInfo().getContentRect()), this.val$fittingMode), null);
                pdfDocument.finishPage(page);
                pdfDocument.writeTo(new FileOutputStream(fileDescriptor.getFileDescriptor()));
                PageRange[] pageRangeArr = new PageRange[PrintHelperKitkat.SCALE_MODE_FIT];
                pageRangeArr[0] = PageRange.ALL_PAGES;
                writeResultCallback.onWriteFinished(pageRangeArr);
            } catch (IOException ioe) {
                Log.e(PrintHelperKitkat.LOG_TAG, "Error writing printed content", ioe);
                writeResultCallback.onWriteFailed(null);
            } catch (Throwable th) {
                if (pdfDocument != null) {
                    pdfDocument.close();
                }
                if (fileDescriptor != null) {
                    try {
                        fileDescriptor.close();
                    } catch (IOException e) {
                    }
                }
                if (maybeGrayscale != this.mBitmap) {
                    maybeGrayscale.recycle();
                }
            }
            if (pdfDocument != null) {
                pdfDocument.close();
            }
            if (fileDescriptor != null) {
                try {
                    fileDescriptor.close();
                } catch (IOException e2) {
                }
            }
            if (maybeGrayscale != this.mBitmap) {
                maybeGrayscale.recycle();
            }
        }
    }

    public interface OnPrintFinishCallback {
        void onFinish();
    }

    PrintHelperKitkat(Context context) {
        this.mDecodeOptions = null;
        this.mLock = new Object();
        this.mScaleMode = SCALE_MODE_FILL;
        this.mColorMode = SCALE_MODE_FILL;
        this.mOrientation = SCALE_MODE_FIT;
        this.mContext = context;
    }

    public void setScaleMode(int scaleMode) {
        this.mScaleMode = scaleMode;
    }

    public int getScaleMode() {
        return this.mScaleMode;
    }

    public void setColorMode(int colorMode) {
        this.mColorMode = colorMode;
    }

    public void setOrientation(int orientation) {
        this.mOrientation = orientation;
    }

    public int getOrientation() {
        return this.mOrientation;
    }

    public int getColorMode() {
        return this.mColorMode;
    }

    public void printBitmap(String jobName, Bitmap bitmap, OnPrintFinishCallback callback) {
        if (bitmap != null) {
            int fittingMode = this.mScaleMode;
            PrintManager printManager = (PrintManager) this.mContext.getSystemService("print");
            MediaSize mediaSize = MediaSize.UNKNOWN_PORTRAIT;
            if (bitmap.getWidth() > bitmap.getHeight()) {
                mediaSize = MediaSize.UNKNOWN_LANDSCAPE;
            }
            printManager.print(jobName, new C00701(jobName, bitmap, fittingMode, callback), new PrintAttributes.Builder().setMediaSize(mediaSize).setColorMode(this.mColorMode).build());
        }
    }

    private Matrix getMatrix(int imageWidth, int imageHeight, RectF content, int fittingMode) {
        Matrix matrix = new Matrix();
        float scale = content.width() / ((float) imageWidth);
        if (fittingMode == SCALE_MODE_FILL) {
            scale = Math.max(scale, content.height() / ((float) imageHeight));
        } else {
            scale = Math.min(scale, content.height() / ((float) imageHeight));
        }
        matrix.postScale(scale, scale);
        matrix.postTranslate((content.width() - (((float) imageWidth) * scale)) / 2.0f, (content.height() - (((float) imageHeight) * scale)) / 2.0f);
        return matrix;
    }

    public void printBitmap(String jobName, Uri imageFile, OnPrintFinishCallback callback) throws FileNotFoundException {
        PrintDocumentAdapter printDocumentAdapter = new C00732(jobName, imageFile, callback, this.mScaleMode);
        PrintManager printManager = (PrintManager) this.mContext.getSystemService("print");
        PrintAttributes.Builder builder = new PrintAttributes.Builder();
        builder.setColorMode(this.mColorMode);
        if (this.mOrientation == SCALE_MODE_FIT) {
            builder.setMediaSize(MediaSize.UNKNOWN_LANDSCAPE);
        } else if (this.mOrientation == SCALE_MODE_FILL) {
            builder.setMediaSize(MediaSize.UNKNOWN_PORTRAIT);
        }
        printManager.print(jobName, printDocumentAdapter, builder.build());
    }

    private Bitmap loadConstrainedBitmap(Uri uri, int maxSideLength) throws FileNotFoundException {
        Bitmap bitmap = null;
        if (maxSideLength <= 0 || uri == null || this.mContext == null) {
            throw new IllegalArgumentException("bad argument to getScaledBitmap");
        }
        Options opt = new Options();
        opt.inJustDecodeBounds = true;
        loadBitmap(uri, opt);
        int w = opt.outWidth;
        int h = opt.outHeight;
        if (w > 0 && h > 0) {
            int imageSide = Math.max(w, h);
            int sampleSize = SCALE_MODE_FIT;
            while (imageSide > maxSideLength) {
                imageSide >>>= SCALE_MODE_FIT;
                sampleSize <<= SCALE_MODE_FIT;
            }
            if (sampleSize > 0 && Math.min(w, h) / sampleSize > 0) {
                Options decodeOptions;
                synchronized (this.mLock) {
                    this.mDecodeOptions = new Options();
                    this.mDecodeOptions.inMutable = true;
                    this.mDecodeOptions.inSampleSize = sampleSize;
                    decodeOptions = this.mDecodeOptions;
                }
                try {
                    bitmap = loadBitmap(uri, decodeOptions);
                    synchronized (this.mLock) {
                        this.mDecodeOptions = null;
                    }
                } catch (Throwable th) {
                    synchronized (this.mLock) {
                    }
                    this.mDecodeOptions = null;
                }
            }
        }
        return bitmap;
    }

    private Bitmap loadBitmap(Uri uri, Options o) throws FileNotFoundException {
        if (uri == null || this.mContext == null) {
            throw new IllegalArgumentException("bad argument to loadBitmap");
        }
        InputStream is = null;
        try {
            is = this.mContext.getContentResolver().openInputStream(uri);
            Bitmap decodeStream = BitmapFactory.decodeStream(is, null, o);
            if (is != null) {
                try {
                    is.close();
                } catch (IOException t) {
                    Log.w(LOG_TAG, "close fail ", t);
                }
            }
            return decodeStream;
        } catch (Throwable th) {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException t2) {
                    Log.w(LOG_TAG, "close fail ", t2);
                }
            }
        }
    }

    private Bitmap convertBitmapForColorMode(Bitmap original, int colorMode) {
        if (colorMode != SCALE_MODE_FIT) {
            return original;
        }
        Bitmap grayscale = Bitmap.createBitmap(original.getWidth(), original.getHeight(), Config.ARGB_8888);
        Canvas c = new Canvas(grayscale);
        Paint p = new Paint();
        ColorMatrix cm = new ColorMatrix();
        cm.setSaturation(0.0f);
        p.setColorFilter(new ColorMatrixColorFilter(cm));
        c.drawBitmap(original, 0.0f, 0.0f, p);
        c.setBitmap(null);
        return grayscale;
    }
}
