Rails.application.routes.draw do
    root to: "credentials#index"
    
    resources :credentials do
        post :prove, on: :collection
    end
end
