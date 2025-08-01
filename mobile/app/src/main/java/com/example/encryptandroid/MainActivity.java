package com.example.encryptandroid;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import com.example.encryptandroid.databinding.ActivityMainBinding;

import org.efurture.encrypt.Encrypt;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'encryptandroid' library on application startup.
    static {
        System.loadLibrary("encrypt");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        tv.setText("hello world");

        tv.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Encrypt.cmd("hello", "test");
            }
        });
    }

}